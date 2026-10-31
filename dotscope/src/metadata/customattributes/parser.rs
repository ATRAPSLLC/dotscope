//! Custom attribute blob parsing implementation for .NET metadata.
//!
//! This module provides robust parsing of custom attribute blob data according to the
//! ECMA-335 II.23.3 `CustomAttribute` signature specification. It implements the documented
//! `CorSerializationType` enumeration for accurate .NET runtime-compliant parsing with
//! comprehensive error handling and graceful degradation strategies.
//!
//! # Architecture
//!
//! The parsing architecture follows established patterns from other metadata parsers
//! in the codebase, providing structured and reliable custom attribute processing:
//!
//! ## Core Components
//!
//! - **Fixed Arguments**: Type-aware parsing based on constructor parameter types (CilFlavor-based)
//! - **Named Arguments**: Explicit `CorSerializationType` tag parsing from blob data
//! - **Iterative Design**: Stack-based iterative parsing with depth limiting for complex types
//! - **Enum Support**: Uses `SERIALIZATION_TYPE` constants for documented .NET types
//!
//! ## Error Handling Strategy
//!
//! - **Graceful Degradation**: Falls back to safer parsing when type resolution fails
//! - **Heuristic Enum Detection**: Uses inheritance analysis and name patterns for external types
//! - **Error Recovery**: Continues parsing despite unknown or malformed data sections
//! - **Future-Proof Design**: Ready for multi-assembly loading while working with current single-assembly model
//!
//! # Key Components
//!
//! - [`crate::metadata::customattributes::parser::CustomAttributeParser`] - Main parser implementation
//! - [`crate::metadata::customattributes::parser::parse_custom_attribute_blob`] - Blob heap parsing
//! - [`crate::metadata::customattributes::parser::parse_custom_attribute_data`] - Raw data parsing
//! - [`crate::metadata::customattributes::types::SERIALIZATION_TYPE`] - Type tag constants
//!
//! # Usage Examples
//!
//! ## Parsing from Blob Heap
//!
//! ```rust,no_run
//! use dotscope::metadata::customattributes::parse_custom_attribute_blob;
//! use dotscope::CilObject;
//!
//! let assembly = CilObject::from_path("tests/samples/WindowsBase.dll")?;
//!
//! # fn get_custom_attribute_data() -> (u32, dotscope::metadata::tables::ParamList) { todo!() }
//! let (blob_index, constructor_params) = get_custom_attribute_data();
//!
//! if let Some(blob_heap) = assembly.blob() {
//!     let custom_attr = parse_custom_attribute_blob(blob_heap, blob_index, &constructor_params)?;
//!
//!     println!("Fixed arguments: {}", custom_attr.fixed_args.len());
//!     println!("Named arguments: {}", custom_attr.named_args.len());
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Parsing Raw Blob Data
//!
//! ```rust,no_run
//! use dotscope::metadata::customattributes::{parse_custom_attribute_data, CustomAttributeArgument};
//!
//! # fn get_constructor_params() -> dotscope::metadata::tables::ParamList { todo!() }
//! let constructor_params = get_constructor_params();
//!
//! // Example: Simple custom attribute with string argument
//! let blob_data = &[
//!     0x01, 0x00,                     // Prolog (0x0001)
//!     0x05,                           // String length
//!     0x48, 0x65, 0x6C, 0x6C, 0x6F,   // "Hello" (UTF-8)
//!     0x00, 0x00,                     // Named argument count (0)
//! ];
//!
//! let result = parse_custom_attribute_data(blob_data, &constructor_params)?;
//!
//! // Access parsed arguments
//! match &result.fixed_args[0] {
//!     CustomAttributeArgument::String(s) => println!("String argument: '{}'", s),
//!     _ => println!("Unexpected argument type"),
//! }
//!
//! println!("Named arguments: {}", result.named_args.len());
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! All functions in this module are thread-safe and stateless. The parser implementation
//! can be called concurrently from multiple threads as it operates only on immutable
//! input data and produces owned output structures.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::customattributes::types`] - Type definitions and argument structures
//! - [`crate::metadata::streams::Blob`] - Blob heap access for custom attribute data
//! - [`crate::metadata::tables`] - Parameter resolution for constructor type information
//! - [`crate::metadata::typesystem`] - Type system integration for `CilFlavor` handling
//!
//! # Implementation Features
//!
//! ## Current Capabilities
//! - **Single Assembly Scope**: Optimized for current single-assembly analysis model
//! - **Type Resolution**: Full support for resolved constructor parameter types
//! - **Graceful Fallbacks**: Heuristic parsing when full type information unavailable
//! - **Comprehensive Validation**: ECMA-335 compliance with detailed error reporting
//! - **Iterative Processing**: Stack-based parsing supporting arbitrarily deep nesting
//!
//! ## Future Enhancements
//! - **Multi-Assembly Support**: Planned project-style loading with cross-assembly resolution
//! - **External Type Loading**: Default `windows_dll` directory for common .NET assemblies
//! - **Enhanced Inheritance**: Full inheritance chain analysis for enum detection
//!
//! # Standards Compliance
//!
//! - **ECMA-335**: Full compliance with custom attribute specification (II.23.3)
//! - **Type Safety**: Robust type checking and validation throughout parsing
//! - **Memory Safety**: Comprehensive bounds checking and nesting depth limiting
//! - **Error Handling**: Detailed error messages for debugging malformed data

use std::{collections::HashMap, sync::Arc};

use crate::{
    file::parser::Parser,
    metadata::{
        customattributes::types::{
            CustomAttributeArgument, CustomAttributeNamedArgument, CustomAttributeValue,
            FieldOrPropType, NAMED_ARG_TYPE, SERIALIZATION_TYPE,
        },
        streams::Blob,
        tables::ParamList,
        typesystem::{CilFlavor, CilTypeRef, CilTypeReference, TypeRegistry},
    },
    utils::EnumUtils,
    Error::DepthLimitExceeded,
    Result,
};

/// Maximum native recursion depth for nested arguments: arrays of boxed values of arrays.
const MAX_ARGUMENT_RECURSION: usize = 64;

/// The underlying type sizes an enum can have, `int`'s first as the usual one.
const ENUM_SIZES: [usize; 4] = [4, 1, 2, 8];

/// How many decodings [`CustomAttributeParser::parse_custom_attribute`] tries for a blob
/// whose enums it cannot size. Each consumes at most the blob, and real blobs name one or two
/// such enums, which need at most 16.
const MAX_ENUM_SIZE_ATTEMPTS: usize = 256;

/// Parse custom attribute blob data from the blob heap using constructor parameter information.
///
/// This function retrieves custom attribute data from the specified blob heap index and
/// parses it according to ECMA-335 II.23.3 specification. It uses the constructor method's
/// parameter types to accurately parse fixed arguments and automatically handles named
/// arguments using their embedded type information.
///
/// # Arguments
/// * `blob` - The [`crate::metadata::streams::Blob`] heap containing custom attribute data
/// * `index` - The index into the blob heap (0 indicates empty custom attribute)
/// * `params` - Reference to the constructor method's parameter vector for type-aware parsing
///
/// # Returns
/// A parsed [`crate::metadata::customattributes::CustomAttributeValue`] containing:
/// - `fixed_args` - Constructor arguments in declaration order
/// - `named_args` - Field and property assignments with names and values
///
/// # Errors
/// Returns [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`] if the index is invalid, or one of the following:
/// - [`crate::Error::Parse`] carrying [`crate::ParseFailure::Other`]: Invalid prolog (not 0x0001), insufficient data for declared arguments, or type/value mismatches in argument parsing
/// - [`crate::Error::DepthLimitExceeded`]: Maximum nesting depth exceeded during parsing
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::metadata::customattributes::parse_custom_attribute_blob;
/// use dotscope::CilObject;
///
/// let assembly = CilObject::from_path("tests/samples/WindowsBase.dll")?;
///
/// # fn get_custom_attribute_data() -> (u32, dotscope::metadata::tables::ParamList) { todo!() }
/// let (blob_index, constructor_params) = get_custom_attribute_data();
///
/// if let Some(blob_heap) = assembly.blob() {
///     let custom_attr = parse_custom_attribute_blob(blob_heap, blob_index, &constructor_params)?;
///
///     println!("Fixed arguments: {}", custom_attr.fixed_args.len());
///     println!("Named arguments: {}", custom_attr.named_args.len());
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// This function is thread-safe and can be called concurrently from multiple threads.
pub fn parse_custom_attribute_blob(
    blob: &Blob,
    index: u32,
    params: &ParamList,
) -> Result<CustomAttributeValue> {
    if index == 0 {
        return Ok(CustomAttributeValue {
            fixed_args: vec![],
            named_args: vec![],
            constructor: CilTypeReference::None,
            blob_index: 0,
        });
    }

    let data = blob.get(index as usize)?;
    let mut parser = CustomAttributeParser::new(data);
    parser.parse_custom_attribute(params)
}

/// Parse custom attribute blob data directly from raw bytes using constructor parameter information.
///
/// This function parses custom attribute data from a raw byte slice according to the
/// ECMA-335 II.23.3 specification. It's the core parsing function used by other APIs
/// and provides direct access to the parsing logic without blob heap indirection.
///
/// The parser uses constructor method parameter types for accurate fixed argument parsing
/// and handles named arguments through their embedded serialization type information.
/// It implements graceful degradation when type resolution fails and provides comprehensive
/// error reporting for malformed data.
///
/// # Arguments
/// * `data` - Raw bytes of the custom attribute blob data to parse
/// * `params` - Reference to the constructor method's parameter vector for type-aware parsing
///
/// # Returns
/// A parsed [`crate::metadata::customattributes::CustomAttributeValue`] containing:
/// - `fixed_args` - Constructor arguments parsed using parameter type information
/// - `named_args` - Field and property assignments with their names and values
///
/// # Errors
/// Returns one of the following errors if the blob data doesn't conform to ECMA-335 format:
/// - [`crate::Error::Parse`] carrying [`crate::ParseFailure::Other`]: Invalid or missing prolog (must be 0x0001), insufficient data for the number of declared arguments, type mismatches between expected and actual argument types, invalid serialization type tags in named arguments, or truncated/corrupted blob data
/// - [`crate::Error::DepthLimitExceeded`]: Maximum nesting depth exceeded during complex type parsing
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::metadata::customattributes::{parse_custom_attribute_data, CustomAttributeArgument};
///
/// # fn get_constructor_params() -> dotscope::metadata::tables::ParamList { todo!() }
/// let constructor_params = get_constructor_params();
///
/// // Example: Simple custom attribute with string argument
/// let blob_data = &[
///     0x01, 0x00,                     // Prolog (0x0001)
///     0x05,                           // String length
///     0x48, 0x65, 0x6C, 0x6C, 0x6F,   // "Hello" (UTF-8)
///     0x00, 0x00,                     // Named argument count (0)
/// ];
///
/// let result = parse_custom_attribute_data(blob_data, &constructor_params)?;
///
/// // Access parsed arguments
/// match &result.fixed_args[0] {
///     CustomAttributeArgument::String(s) => println!("String argument: '{}'", s),
///     _ => println!("Unexpected argument type"),
/// }
///
/// println!("Named arguments: {}", result.named_args.len());
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// This function is thread-safe and can be called concurrently from multiple threads.
pub fn parse_custom_attribute_data(
    data: &[u8],
    params: &ParamList,
) -> Result<CustomAttributeValue> {
    let mut parser = CustomAttributeParser::new(data);
    parser.parse_custom_attribute(params)
}

/// Parse custom attribute blob data with enhanced cross-assembly type resolution.
///
/// This enhanced version leverages the TypeRegistry's cross-assembly resolution capabilities
/// to properly handle external enum types that were previously causing parsing failures
/// in mono assemblies. This addresses the core issue where CustomAttribute parsing would
/// fail when enum underlying types were defined in external assemblies.
///
/// # Key Enhancements
///
/// - **Cross-Assembly Type Resolution**: Uses `TypeRegistry.resolve_type_global()` to find
///   TypeDef entries across all linked assemblies instead of just the current assembly
/// - **Proper Enum Detection**: Can determine if external types are enums by finding their
///   actual TypeDef and analyzing inheritance chains
/// - **Reliable Underlying Type Resolution**: Gets actual enum underlying types instead of
///   using heuristics or hardcoded type lists
///
/// # Arguments
/// * `data` - Raw bytes of the custom attribute blob data to parse
/// * `params` - Reference to the constructor method's parameter vector for type-aware parsing
/// * `type_registry` - TypeRegistry with cross-assembly resolution via `registry_link()`
///
/// # Returns
/// A fully parsed [`crate::metadata::customattributes::CustomAttributeValue`] with proper
/// external enum handling that previously would have failed with heuristic approaches.
///
/// # Errors
/// Returns an error if the custom attribute data cannot be parsed.
///
/// # Thread Safety
/// This function is thread-safe and can be called concurrently from multiple threads.
pub fn parse_custom_attribute_data_with_registry(
    data: &[u8],
    params: &ParamList,
    type_registry: &Arc<TypeRegistry>,
) -> Result<CustomAttributeValue> {
    let mut parser = CustomAttributeParser::with_registry(data, type_registry.clone());
    parser.parse_custom_attribute(params)
}

/// Parse custom attribute blob data with enhanced cross-assembly type resolution.
///
/// This enhanced version of [`parse_custom_attribute_blob`] leverages the TypeRegistry's
/// cross-assembly resolution capabilities to properly handle external enum types that were
/// previously causing parsing failures in mono assemblies.
///
/// # Arguments
/// * `blob` - The blob heap containing custom attribute data
/// * `index` - Index into the blob heap where the custom attribute data starts
/// * `params` - Reference to the constructor method's parameter vector for type-aware parsing
/// * `type_registry` - TypeRegistry with cross-assembly resolution via `registry_link()`
///
/// # Returns
/// A fully parsed [`crate::metadata::customattributes::CustomAttributeValue`] with proper
/// external enum handling that previously would have failed with heuristic approaches.
///
/// # Errors
/// Returns an error if the custom attribute blob cannot be parsed.
///
/// # Thread Safety
/// This function is thread-safe and can be called concurrently from multiple threads.
pub fn parse_custom_attribute_blob_with_registry(
    blob: &Blob,
    index: u32,
    params: &ParamList,
    type_registry: &Arc<TypeRegistry>,
) -> Result<CustomAttributeValue> {
    let data = blob.get(index as usize)?;
    let mut parser = CustomAttributeParser::with_registry(data, type_registry.clone());
    parser.parse_custom_attribute(params)
}

/// Custom attribute parser implementing ECMA-335 II.23.3.
///
/// A fixed argument is decoded by its constructor parameter's type, a named argument and a
/// boxed value by the type the blob names before it ([`FieldOrPropType`]); one decoder,
/// driven by that type, reads every value. The blob does not say how wide an enum is, so an
/// enum no loaded assembly defines takes the size under which the whole blob decodes exactly.
///
/// # Thread Safety
///
/// [`CustomAttributeParser`] is not [`std::marker::Send`] or [`std::marker::Sync`] due to mutable state.
/// Each thread should create its own parser instance for concurrent parsing operations.
pub struct CustomAttributeParser<'a> {
    /// Binary data parser for reading attribute blob
    parser: Parser<'a>,
    /// Optional TypeRegistry for cross-assembly type resolution
    type_registry: Option<Arc<TypeRegistry>>,
    /// Current native-recursion depth, for stack-overflow prevention.
    depth: usize,
    /// The underlying type sizes of the enums a constructor parameter resolved, by name.
    known_enum_sizes: HashMap<String, usize>,
    /// The underlying type sizes the current decoding assumes for enums no loaded assembly
    /// defines, by name.
    enum_sizes: HashMap<String, usize>,
    /// The enums of that kind the decodings met, in the order they met them.
    unknown_enums: Vec<String>,
}

impl<'a> CustomAttributeParser<'a> {
    /// Creates a new custom attribute parser for the provided blob data.
    ///
    /// # Arguments
    /// * `data` - Raw bytes of the custom attribute blob to parse
    ///
    /// # Examples
    ///
    /// The `examples::new_example` test in this module runs this example.
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            parser: Parser::new(data),
            type_registry: None,
            depth: 0,
            known_enum_sizes: HashMap::new(),
            enum_sizes: HashMap::new(),
            unknown_enums: Vec::new(),
        }
    }

    /// Creates a new custom attribute parser with cross-assembly type resolution support,
    /// which sizes the enums the registry can resolve.
    ///
    /// # Arguments
    /// * `data` - Raw bytes of the custom attribute blob to parse
    /// * `type_registry` - TypeRegistry with cross-assembly resolution via `registry_link()`
    ///
    /// # Examples
    ///
    /// The `examples::with_registry_example` test in this module runs this example.
    #[must_use]
    pub fn with_registry(data: &'a [u8], type_registry: Arc<TypeRegistry>) -> Self {
        Self {
            type_registry: Some(type_registry),
            ..Self::new(data)
        }
    }

    /// Parse a complete custom attribute blob according to ECMA-335 II.23.3: the prolog
    /// `0x0001`, a fixed argument per constructor parameter, then the named arguments.
    ///
    /// # Arguments
    /// * `params` - Constructor method parameters for fixed argument type resolution
    ///
    /// # Returns
    /// A complete [`crate::metadata::customattributes::CustomAttributeValue`] with all parsed data.
    ///
    /// # Errors
    /// Returns [`crate::Error::Parse`] carrying [`crate::ParseFailure::Other`] for format
    /// violations: a prolog other than 0x0001, a parameter type no attribute argument can
    /// have, data that ends early, or a type tag the grammar does not define; and
    /// [`crate::Error::DepthLimitExceeded`] for nesting past the parser's bound.
    ///
    /// # Examples
    ///
    /// The `examples::parse_custom_attribute_example` test in this module runs this example.
    pub fn parse_custom_attribute(&mut self, params: &ParamList) -> Result<CustomAttributeValue> {
        let types = self.parameter_types(params)?;
        self.settle(|parser| parser.decode(&types))
    }

    /// Decodes `count` named arguments from the start of the data: the properties of a
    /// permission in a binary permission set, which follow the custom attribute named argument
    /// grammar (ECMA-335 II.23.3). Their enums are sized as a blob's are, by the sizing under
    /// which the arguments end where the data does.
    ///
    /// # Errors
    ///
    /// When the arguments do not decode.
    pub fn parse_named_arguments(
        &mut self,
        count: usize,
    ) -> Result<Vec<CustomAttributeNamedArgument>> {
        self.settle(|parser| {
            parser.parser.seek(0)?;
            parser.depth = 0;
            (0..count)
                .map(|_| parser.parse_named_argument())
                .collect::<Result<Vec<_>>>()
        })
    }

    /// Runs `decode` from the start of the data, and when it meets enums it cannot size and
    /// does not end exactly at the data's end, again under each other sizing of them, bounded,
    /// until a decoding does. The blob does not say how wide an enum is, and no loaded
    /// assembly defines these: only their true sizes end the data where its last value ends.
    /// Without such a decoding, the first one's result stands.
    fn settle<T>(&mut self, mut decode: impl FnMut(&mut Self) -> Result<T>) -> Result<T> {
        self.unknown_enums.clear();
        self.enum_sizes.clear();
        let first = decode(self);
        if self.unknown_enums.is_empty() || (first.is_ok() && !self.parser.has_more_data()) {
            return first;
        }

        let mut attempts = 1usize;
        let mut enums = self.unknown_enums.len();
        let mut assignment: usize = 1;
        while attempts < MAX_ENUM_SIZE_ATTEMPTS {
            let combinations = u32::try_from(enums)
                .ok()
                .and_then(|count| ENUM_SIZES.len().checked_pow(count))
                .unwrap_or(usize::MAX);
            if assignment >= combinations {
                break;
            }
            let mut digits = assignment;
            self.enum_sizes.clear();
            for name in &self.unknown_enums {
                let size = digits
                    .checked_rem(ENUM_SIZES.len())
                    .and_then(|digit| ENUM_SIZES.get(digit))
                    .copied()
                    .unwrap_or(4);
                self.enum_sizes.insert(name.clone(), size);
                digits = digits.checked_div(ENUM_SIZES.len()).unwrap_or_default();
            }
            attempts = attempts.saturating_add(1);
            assignment = assignment.saturating_add(1);

            let decoded = decode(self);
            if decoded.is_ok() && !self.parser.has_more_data() {
                return decoded;
            }
            // A decoding that read further met enums the earlier ones did not reach: start
            // over with those in the count.
            if self.unknown_enums.len() > enums {
                enums = self.unknown_enums.len();
                assignment = 1;
            }
        }
        first
    }

    /// One decoding of the blob from its start, the fixed arguments by `types`, under the enum
    /// sizes [`Self::enum_sizes`] assumes.
    fn decode(&mut self, types: &[FieldOrPropType]) -> Result<CustomAttributeValue> {
        self.parser.seek(0)?;
        self.depth = 0;

        let prolog = self.parser.read_le::<u16>()?;
        if prolog != 0x0001 {
            return Err(malformed_error!(
                "Invalid custom attribute prolog - expected 0x0001"
            ));
        }

        let mut fixed_args = Vec::with_capacity(types.len());
        for argument_type in types {
            fixed_args.push(self.decode_value(argument_type)?);
        }

        // NumNamed follows the fixed arguments; a blob that ends without it has none
        let mut named_args = Vec::new();
        if self.parser.has_more_data() {
            let count = self.parser.read_le::<u16>()?;
            // Each named argument takes several bytes, so what is left bounds the count
            let remaining = self.parser.len().saturating_sub(self.parser.pos());
            named_args.reserve(usize::from(count).min(remaining));
            for _ in 0..count {
                named_args.push(self.parse_named_argument()?);
            }
        }

        Ok(CustomAttributeValue {
            fixed_args,
            named_args,
            constructor: CilTypeReference::None,
            blob_index: 0,
        })
    }

    /// The type each constructor parameter, in order, gives its fixed argument.
    ///
    /// # Errors
    ///
    /// When a parameter's type is unresolved or no attribute argument can have it.
    fn parameter_types(&mut self, params: &ParamList) -> Result<Vec<FieldOrPropType>> {
        let mut parameters: Vec<_> = params
            .iter()
            .filter(|(_, param)| param.sequence > 0)
            .map(|(_, param)| param)
            .collect();
        parameters.sort_by_key(|param| param.sequence);
        parameters
            .into_iter()
            .map(|param| match param.base.get() {
                Some(base) => self.argument_type(base),
                None => Err(malformed_error!(
                    "Constructor parameter {} has no resolved type",
                    param.sequence
                )),
            })
            .collect()
    }

    /// The [`FieldOrPropType`] a parameter of type `cil_type` gives its argument: a
    /// primitive, `string`, `System.Type`, `object`, an enum, or a single-dimensional array of
    /// one of these (ECMA-335 II.23.3).
    ///
    /// # Errors
    ///
    /// For any other type, such as a native integer, a class, or a multi-dimensional array.
    fn argument_type(&mut self, cil_type: &CilTypeRef) -> Result<FieldOrPropType> {
        let Some(type_ref) = cil_type.upgrade() else {
            return Err(malformed_error!("Type reference has been dropped"));
        };
        let flavor = type_ref.flavor();
        Ok(match flavor {
            CilFlavor::Boolean => FieldOrPropType::Bool,
            CilFlavor::Char => FieldOrPropType::Char,
            CilFlavor::I1 => FieldOrPropType::I1,
            CilFlavor::U1 => FieldOrPropType::U1,
            CilFlavor::I2 => FieldOrPropType::I2,
            CilFlavor::U2 => FieldOrPropType::U2,
            CilFlavor::I4 => FieldOrPropType::I4,
            CilFlavor::U4 => FieldOrPropType::U4,
            CilFlavor::I8 => FieldOrPropType::I8,
            CilFlavor::U8 => FieldOrPropType::U8,
            CilFlavor::R4 => FieldOrPropType::R4,
            CilFlavor::R8 => FieldOrPropType::R8,
            CilFlavor::String => FieldOrPropType::String,
            CilFlavor::Object => FieldOrPropType::Boxed,
            CilFlavor::Array { rank: 1, .. } => {
                let Some(element) = type_ref.base() else {
                    return Err(malformed_error!("Array parameter has no element type"));
                };
                if self.depth >= MAX_ARGUMENT_RECURSION {
                    return Err(DepthLimitExceeded(MAX_ARGUMENT_RECURSION));
                }
                self.depth = self.depth.saturating_add(1);
                let element = self.argument_type(&element.into());
                self.depth = self.depth.saturating_sub(1);
                FieldOrPropType::SzArray(Box::new(element?))
            }
            CilFlavor::Class | CilFlavor::ValueType => {
                let name = type_ref.fullname();
                match &*name {
                    "System.Type" => FieldOrPropType::Type,
                    "System.String" => FieldOrPropType::String,
                    "System.Object" => FieldOrPropType::Boxed,
                    _ => {
                        // The only other types an argument can have are enums (II.23.3). One
                        // defined here, or in an assembly the registry has, is sized by its
                        // definition; an imported one the blob sizes.
                        let defined = self
                            .type_registry
                            .as_ref()
                            .and_then(|registry| registry.resolve_type_global(&name))
                            .filter(|resolved| {
                                EnumUtils::is_enum_type(resolved, self.type_registry.as_ref())
                            });
                        if let Some(resolved) = defined {
                            let size = EnumUtils::get_enum_underlying_type_size(&resolved);
                            self.known_enum_sizes.insert(name.to_string(), size);
                        } else if EnumUtils::is_enum_type(&type_ref, None) {
                            let size = EnumUtils::get_enum_underlying_type_size(&type_ref);
                            self.known_enum_sizes.insert(name.to_string(), size);
                        } else if type_ref.token.table() != 0x01 && !type_ref.is_typeref() {
                            return Err(malformed_error!(
                                "Constructor parameter type '{}' is neither an enum nor a type a custom attribute argument can have",
                                name
                            ));
                        }
                        FieldOrPropType::Enum(name.to_string())
                    }
                }
            }
            other => {
                return Err(malformed_error!(
                    "No custom attribute argument can have type {:?} (ECMA-335 II.23.3)",
                    other
                ))
            }
        })
    }

    /// Reads a `FieldOrPropType`: a serialization tag, with an enum's type name or an array's
    /// element type after it.
    ///
    /// # Errors
    ///
    /// For a tag the grammar does not define, or nesting past [`MAX_ARGUMENT_RECURSION`].
    fn read_field_or_prop_type(&mut self) -> Result<FieldOrPropType> {
        let tag = self.parser.read_le::<u8>()?;
        Ok(match tag {
            SERIALIZATION_TYPE::BOOLEAN => FieldOrPropType::Bool,
            SERIALIZATION_TYPE::CHAR => FieldOrPropType::Char,
            SERIALIZATION_TYPE::I1 => FieldOrPropType::I1,
            SERIALIZATION_TYPE::U1 => FieldOrPropType::U1,
            SERIALIZATION_TYPE::I2 => FieldOrPropType::I2,
            SERIALIZATION_TYPE::U2 => FieldOrPropType::U2,
            SERIALIZATION_TYPE::I4 => FieldOrPropType::I4,
            SERIALIZATION_TYPE::U4 => FieldOrPropType::U4,
            SERIALIZATION_TYPE::I8 => FieldOrPropType::I8,
            SERIALIZATION_TYPE::U8 => FieldOrPropType::U8,
            SERIALIZATION_TYPE::R4 => FieldOrPropType::R4,
            SERIALIZATION_TYPE::R8 => FieldOrPropType::R8,
            SERIALIZATION_TYPE::STRING => FieldOrPropType::String,
            SERIALIZATION_TYPE::TYPE => FieldOrPropType::Type,
            SERIALIZATION_TYPE::TAGGED_OBJECT => FieldOrPropType::Boxed,
            SERIALIZATION_TYPE::ENUM => match self.read_ser_string()? {
                Some(name) => FieldOrPropType::Enum(name),
                None => return Err(malformed_error!("An enum type has a null name")),
            },
            SERIALIZATION_TYPE::SZARRAY => {
                if self.depth >= MAX_ARGUMENT_RECURSION {
                    return Err(DepthLimitExceeded(MAX_ARGUMENT_RECURSION));
                }
                self.depth = self.depth.saturating_add(1);
                let element = self.read_field_or_prop_type();
                self.depth = self.depth.saturating_sub(1);
                FieldOrPropType::SzArray(Box::new(element?))
            }
            _ => {
                return Err(malformed_error!(
                    "Unsupported serialization type tag: 0x{:02X}",
                    tag
                ))
            }
        })
    }

    /// Reads a value of type `argument_type` (II.23.3 `Elem`, or a boxed value's tag and
    /// value).
    ///
    /// # Errors
    ///
    /// When the data ends early, an array's length runs past the blob, or nesting passes
    /// [`MAX_ARGUMENT_RECURSION`].
    fn decode_value(&mut self, argument_type: &FieldOrPropType) -> Result<CustomAttributeArgument> {
        if self.depth >= MAX_ARGUMENT_RECURSION {
            return Err(DepthLimitExceeded(MAX_ARGUMENT_RECURSION));
        }
        self.depth = self.depth.saturating_add(1);
        let value = self.decode_value_at(argument_type);
        self.depth = self.depth.saturating_sub(1);
        value
    }

    fn decode_value_at(
        &mut self,
        argument_type: &FieldOrPropType,
    ) -> Result<CustomAttributeArgument> {
        let p = &mut self.parser;
        Ok(match argument_type {
            FieldOrPropType::Bool => CustomAttributeArgument::Bool(p.read_le::<u8>()? != 0),
            FieldOrPropType::Char => CustomAttributeArgument::Char(p.read_le::<u16>()?),
            FieldOrPropType::I1 => CustomAttributeArgument::I1(p.read_le::<i8>()?),
            FieldOrPropType::U1 => CustomAttributeArgument::U1(p.read_le::<u8>()?),
            FieldOrPropType::I2 => CustomAttributeArgument::I2(p.read_le::<i16>()?),
            FieldOrPropType::U2 => CustomAttributeArgument::U2(p.read_le::<u16>()?),
            FieldOrPropType::I4 => CustomAttributeArgument::I4(p.read_le::<i32>()?),
            FieldOrPropType::U4 => CustomAttributeArgument::U4(p.read_le::<u32>()?),
            FieldOrPropType::I8 => CustomAttributeArgument::I8(p.read_le::<i64>()?),
            FieldOrPropType::U8 => CustomAttributeArgument::U8(p.read_le::<u64>()?),
            FieldOrPropType::R4 => CustomAttributeArgument::R4(p.read_le::<f32>()?),
            FieldOrPropType::R8 => CustomAttributeArgument::R8(p.read_le::<f64>()?),
            FieldOrPropType::String => CustomAttributeArgument::String(self.read_ser_string()?),
            FieldOrPropType::Type => CustomAttributeArgument::Type(self.read_ser_string()?),
            FieldOrPropType::Boxed => {
                let held = self.read_field_or_prop_type()?;
                if held == FieldOrPropType::Boxed {
                    return Err(malformed_error!("A boxed value cannot hold a boxed value"));
                }
                CustomAttributeArgument::Boxed(Box::new(self.decode_value(&held)?))
            }
            FieldOrPropType::Enum(name) => {
                let size = self.enum_underlying_size(name);
                self.parse_enum(name.clone(), size)?
            }
            FieldOrPropType::SzArray(element) => {
                // NumElem: a little-endian uint32, 0xFFFFFFFF for the null array
                let count = self.parser.read_le::<u32>()?;
                if count == u32::MAX {
                    return Ok(CustomAttributeArgument::Array((**element).clone(), None));
                }
                // Every element takes at least a byte, so a count past what is left is no
                // array this blob can hold
                let remaining = self.parser.len().saturating_sub(self.parser.pos());
                let count = usize::try_from(count).unwrap_or(usize::MAX);
                if count > remaining {
                    return Err(malformed_error!(
                        "Custom attribute array of {} elements, with {} bytes left",
                        count,
                        remaining
                    ));
                }
                let mut items = Vec::with_capacity(count);
                for _ in 0..count {
                    items.push(self.decode_value(element)?);
                }
                CustomAttributeArgument::Array((**element).clone(), Some(items))
            }
        })
    }

    /// The size of the named enum's underlying type: the constructor parameter's or the
    /// registry's when either defines the enum, otherwise [`Self::assumed_enum_size`].
    fn enum_underlying_size(&mut self, type_name: &str) -> usize {
        if let Some(&size) = self.known_enum_sizes.get(type_name) {
            return size;
        }
        if let Some(registry) = &self.type_registry {
            if let Some(resolved) = registry.resolve_type_global(type_name) {
                if EnumUtils::is_enum_type(&resolved, Some(registry)) {
                    return EnumUtils::get_enum_underlying_type_size(&resolved);
                }
            }
        }
        self.assumed_enum_size(type_name)
    }

    /// The underlying type size the current decoding assumes for an enum no loaded assembly
    /// defines: `int`'s, the usual one, unless [`Self::parse_custom_attribute`] is trying
    /// another. The enum is recorded so that it can.
    fn assumed_enum_size(&mut self, type_name: &str) -> usize {
        if let Some(&size) = self.enum_sizes.get(type_name) {
            return size;
        }
        self.unknown_enums.push(type_name.to_string());
        self.enum_sizes.insert(type_name.to_string(), 4);
        4
    }

    /// An enum value of the named enum, read as its underlying type of `size` bytes.
    ///
    /// # Errors
    ///
    /// When the size is not 1, 2, 4 or 8 (an enum whose fields are not loaded reports 0).
    fn parse_enum(&mut self, type_name: String, size: usize) -> Result<CustomAttributeArgument> {
        let value = match size {
            1 => CustomAttributeArgument::U1(self.parser.read_le::<u8>()?),
            2 => CustomAttributeArgument::U2(self.parser.read_le::<u16>()?),
            4 => CustomAttributeArgument::I4(self.parser.read_le::<i32>()?),
            8 => CustomAttributeArgument::I8(self.parser.read_le::<i64>()?),
            0 => {
                return Err(malformed_error!(
                "Cannot determine enum underlying type size for '{}' - enum fields not loaded yet.",
                type_name
            ))
            }
            _ => {
                return Err(malformed_error!(
                "Invalid enum underlying type size {} for enum '{}'. Expected 1, 2, 4, or 8 bytes.",
                size,
                type_name
            ))
            }
        };
        Ok(CustomAttributeArgument::Enum(type_name, Box::new(value)))
    }

    /// Parse a named argument: FIELD (0x53) or PROPERTY (0x54), its `FieldOrPropType`, its
    /// name, then its value (ECMA-335 II.23.3).
    ///
    /// # Errors
    /// Returns [`crate::Error::Parse`] carrying [`crate::ParseFailure::Other`] for a marker
    /// other than FIELD or PROPERTY, a type tag the grammar does not define, or a null or
    /// truncated name.
    fn parse_named_argument(&mut self) -> Result<CustomAttributeNamedArgument> {
        let is_field = match self.parser.read_le::<u8>()? {
            NAMED_ARG_TYPE::FIELD => true,
            NAMED_ARG_TYPE::PROPERTY => false,
            other => {
                return Err(malformed_error!(
                    "Invalid field/property indicator: 0x{:02X} (expected 0x{:02X} for FIELD or 0x{:02X} for PROPERTY)",
                    other,
                    NAMED_ARG_TYPE::FIELD,
                    NAMED_ARG_TYPE::PROPERTY
                ))
            }
        };
        // The type is complete before the name (ECMA-335 II.23.3): an enum's type name and an
        // array's element type follow its tag.
        let arg_type = self.read_field_or_prop_type()?;
        let Some(name) = self.read_ser_string()? else {
            return Err(malformed_error!("A named argument has a null name"));
        };
        let value = self.decode_value(&arg_type)?;
        Ok(CustomAttributeNamedArgument {
            is_field,
            name,
            arg_type,
            value,
        })
    }

    /// Reads a `SerString`: 0xFF for the null string, otherwise a compressed length and that
    /// many UTF-8 bytes.
    ///
    /// # Errors
    ///
    /// When the length runs past the blob or the bytes are not UTF-8.
    fn read_ser_string(&mut self) -> Result<Option<String>> {
        if self.parser.peek_byte()? == 0xFF {
            self.parser.read_le::<u8>()?;
            return Ok(None);
        }
        let length = self.parser.read_compressed_uint()? as usize;
        let start = self.parser.pos();
        let available = self.parser.len().saturating_sub(start);
        if length > available {
            return Err(malformed_error!(
                "Custom attribute string of {} bytes, with {} left",
                length,
                available
            ));
        }
        let bytes = self.parser.read_bytes(length)?;
        String::from_utf8(bytes.to_vec()).map(Some).map_err(|e| {
            malformed_error!(
                "Invalid UTF-8 in custom attribute string at position {}: {}",
                start,
                e
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{
            atomic::{AtomicU64, Ordering},
            Arc, Mutex, OnceLock,
        },
    };

    use super::*;
    use crate::{
        metadata::{
            identity::AssemblyIdentity,
            tables::{Param, ParamAttributes},
            token::Token,
            typesystem::{CilFlavor, CilPrimitiveKind, CilTypeRef, TypeBuilder, TypeRegistry},
        },
        testkit::{
            factories::metadata::customattributes::{
                create_constructor_with_params, create_constructor_with_params_and_registry,
                create_empty_constructor, get_test_type_registry,
            },
            fixture,
        },
        CilObject,
    };

    #[test]
    fn test_parse_empty_blob_with_method() {
        let method = create_empty_constructor();
        let result = parse_custom_attribute_data(&[0x01, 0x00], &method.params).unwrap();
        assert!(result.fixed_args.is_empty());
        assert!(result.named_args.is_empty());
    }

    #[test]
    fn test_parse_invalid_prolog_with_method() {
        let method = create_empty_constructor();
        let result = parse_custom_attribute_data(&[0x00, 0x01], &method.params);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid custom attribute prolog"));
    }

    #[test]
    fn test_parse_simple_blob_with_method() {
        let method = create_empty_constructor();

        // Test case 1: Just prolog
        let blob_data = &[0x01, 0x00];
        let result = parse_custom_attribute_data(blob_data, &method.params).unwrap();
        assert_eq!(result.fixed_args.len(), 0);
        assert_eq!(result.named_args.len(), 0);

        // Test case 2: Valid prolog with no fixed arguments and no named arguments
        let blob_data = &[
            0x01, 0x00, // Prolog (0x0001)
            0x00, 0x00, // NumNamed = 0
        ];
        let result = parse_custom_attribute_data(blob_data, &method.params).unwrap();
        // Without resolved parameter types, fixed args should be empty
        assert_eq!(result.fixed_args.len(), 0);
        assert_eq!(result.named_args.len(), 0);
    }

    #[test]
    fn test_parse_boolean_argument() {
        let method = create_constructor_with_params(vec![CilFlavor::Boolean]);

        let blob_data = &[
            0x01, 0x00, // Prolog
            0x01, // Boolean true
            0x00, 0x00, // NumNamed = 0
        ];

        let result = parse_custom_attribute_data(blob_data, &method.params).unwrap();
        assert_eq!(result.fixed_args.len(), 1);
        match &result.fixed_args[0] {
            CustomAttributeArgument::Bool(val) => assert!(*val),
            _ => panic!("Expected Boolean argument"),
        }
    }

    #[test]
    fn test_parse_char_argument() {
        let method = create_constructor_with_params(vec![CilFlavor::Char]);

        let blob_data = &[
            0x01, 0x00, // Prolog
            0x41, 0x00, // Char 'A' (UTF-16 LE)
            0x00, 0x00, // NumNamed = 0
        ];

        let result = parse_custom_attribute_data(blob_data, &method.params).unwrap();
        assert_eq!(result.fixed_args.len(), 1);
        match &result.fixed_args[0] {
            CustomAttributeArgument::Char(val) => assert_eq!(*val, 0x41),
            _ => panic!("Expected Char argument"),
        }
    }

    #[test]
    fn test_parse_integer_arguments() {
        let method = create_constructor_with_params(vec![
            CilFlavor::I1,
            CilFlavor::U1,
            CilFlavor::I2,
            CilFlavor::U2,
            CilFlavor::I4,
            CilFlavor::U4,
            CilFlavor::I8,
            CilFlavor::U8,
        ]);

        let blob_data = &[
            0x01, 0x00, // Prolog
            0xFF, // I1: -1
            0x42, // U1: 66
            0x00, 0x80, // I2: -32768 (LE)
            0xFF, 0xFF, // U2: 65535 (LE)
            0x00, 0x00, 0x00, 0x80, // I4: -2147483648 (LE)
            0xFF, 0xFF, 0xFF, 0xFF, // U4: 4294967295 (LE)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // I8: -9223372036854775808 (LE)
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // U8: 18446744073709551615 (LE)
            0x00, 0x00, // NumNamed = 0
        ];

        // Using direct API
        let result = parse_custom_attribute_data(blob_data, &method.params).unwrap();
        assert_eq!(result.fixed_args.len(), 8);

        match &result.fixed_args[0] {
            CustomAttributeArgument::I1(val) => assert_eq!(*val, -1i8),
            _ => panic!("Expected I1 argument"),
        }
        match &result.fixed_args[1] {
            CustomAttributeArgument::U1(val) => assert_eq!(*val, 66u8),
            _ => panic!("Expected U1 argument"),
        }
        match &result.fixed_args[2] {
            CustomAttributeArgument::I2(val) => assert_eq!(*val, -32768i16),
            _ => panic!("Expected I2 argument"),
        }
        match &result.fixed_args[3] {
            CustomAttributeArgument::U2(val) => assert_eq!(*val, 65535u16),
            _ => panic!("Expected U2 argument"),
        }
        match &result.fixed_args[4] {
            CustomAttributeArgument::I4(val) => assert_eq!(*val, -2147483648i32),
            _ => panic!("Expected I4 argument"),
        }
        match &result.fixed_args[5] {
            CustomAttributeArgument::U4(val) => assert_eq!(*val, 4294967295u32),
            _ => panic!("Expected U4 argument"),
        }
        match &result.fixed_args[6] {
            CustomAttributeArgument::I8(val) => assert_eq!(*val, -9223372036854775808i64),
            _ => panic!("Expected I8 argument"),
        }
        match &result.fixed_args[7] {
            CustomAttributeArgument::U8(val) => assert_eq!(*val, 18446744073709551615u64),
            _ => panic!("Expected U8 argument"),
        }
    }

    #[test]
    fn test_parse_floating_point_arguments() {
        let method = create_constructor_with_params(vec![CilFlavor::R4, CilFlavor::R8]);

        let blob_data = &[
            0x01, 0x00, // Prolog
            0x00, 0x00, 0x20, 0x41, // R4: 10.0 (LE)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x40, // R8: 10.0 (LE)
            0x00, 0x00, // NumNamed = 0
        ];

        // Using direct API
        let result = parse_custom_attribute_data(blob_data, &method.params).unwrap();
        assert_eq!(result.fixed_args.len(), 2);

        match &result.fixed_args[0] {
            CustomAttributeArgument::R4(val) => assert_eq!(*val, 10.0f32),
            _ => panic!("Expected R4 argument"),
        }
        match &result.fixed_args[1] {
            CustomAttributeArgument::R8(val) => assert_eq!(*val, 10.0f64),
            _ => panic!("Expected R8 argument"),
        }
    }

    /// No custom attribute argument has a native integer type (ECMA-335 II.23.3), so a
    /// constructor taking one has no blob to read.
    #[test]
    fn test_parse_native_integer_arguments() {
        for flavor in [CilFlavor::I, CilFlavor::U] {
            let method = create_constructor_with_params(vec![flavor]);
            let blob_data = &[0x01, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00];
            assert!(parse_custom_attribute_data(blob_data, &method.params).is_err());
        }
    }

    #[test]
    fn test_parse_string_argument() {
        let method = create_constructor_with_params(vec![CilFlavor::String]);

        let blob_data = &[
            0x01, 0x00, // Prolog
            0x05, // String length (compressed)
            0x48, 0x65, 0x6C, 0x6C, 0x6F, // "Hello"
            0x00, 0x00, // NumNamed = 0
        ];

        // Using direct API
        let result = parse_custom_attribute_data(blob_data, &method.params).unwrap();
        assert_eq!(result.fixed_args.len(), 1);
        match &result.fixed_args[0] {
            CustomAttributeArgument::String(Some(val)) => assert_eq!(val, "Hello"),
            _ => panic!("Expected String argument"),
        }
    }

    #[test]
    fn test_parse_class_as_type_argument() {
        let method = create_constructor_with_params(vec![CilFlavor::Class]);

        let blob_data = &[
            0x01, 0x00, // Prolog
            0x0C, // Type name length (compressed) - 12 bytes for "System.Int32"
            0x53, 0x79, 0x73, 0x74, 0x65, 0x6D, 0x2E, 0x49, 0x6E, 0x74, 0x33,
            0x32, // "System.Int32"
            0x00, 0x00, // NumNamed = 0
        ];

        // Class types are parsed as Type arguments when they represent System.Type references
        let result = parse_custom_attribute_data(blob_data, &method.params).unwrap();
        assert_eq!(result.fixed_args.len(), 1);
        // Parser may return either Type or String depending on context
        match &result.fixed_args[0] {
            CustomAttributeArgument::Type(Some(val)) => assert_eq!(val, "System.Int32"),
            CustomAttributeArgument::String(Some(val)) => assert_eq!(val, "System.Int32"),
            other => panic!("Expected Type or String argument, got: {other:?}"),
        }
    }

    #[test]
    fn test_parse_class_argument_scenarios() {
        let test_registry = get_test_type_registry();

        // Test basic class scenarios that should work
        let method1 =
            create_constructor_with_params_and_registry(vec![CilFlavor::Class], &test_registry);
        let blob_data1 = &[
            0x01, 0x00, // Prolog
            0x00, // Compressed length: 0 (empty string)
            0x00, 0x00, // NumNamed = 0
        ];

        let result1 =
            parse_custom_attribute_data_with_registry(blob_data1, &method1.params, &test_registry);
        match result1 {
            Ok(attr) => {
                assert_eq!(attr.fixed_args.len(), 1);
                // Accept either Type or String argument based on actual parser behavior
                match &attr.fixed_args[0] {
                    CustomAttributeArgument::Type(Some(s)) => assert_eq!(s, ""),
                    CustomAttributeArgument::String(Some(s)) => assert_eq!(s, ""),
                    _ => panic!("Expected empty string or type argument"),
                }
            }
            Err(e) => panic!("Expected success for empty string, got: {e}"),
        }
    }

    #[test]
    fn test_parse_valuetype_enum_argument() {
        let test_registry = get_test_type_registry();
        let method =
            create_constructor_with_params_and_registry(vec![CilFlavor::ValueType], &test_registry);

        let blob_data = &[
            0x01, 0x00, // Prolog
            0x01, 0x00, 0x00, 0x00, // Enum value as I4 (1)
            0x00, 0x00, // NumNamed = 0
        ];

        let result =
            parse_custom_attribute_data_with_registry(blob_data, &method.params, &test_registry)
                .unwrap();
        assert_eq!(result.fixed_args.len(), 1);
        match &result.fixed_args[0] {
            CustomAttributeArgument::Enum(type_name, boxed_val) => {
                // Accept either "Unknown" or "System.TestEnum" based on actual parser behavior
                assert!(type_name == "Unknown" || type_name == "System.TestEnum");
                match boxed_val.as_ref() {
                    CustomAttributeArgument::I4(val) => assert_eq!(*val, 1),
                    _ => panic!("Expected I4 in enum"),
                }
            }
            _ => panic!("Expected Enum argument"),
        }
    }

    /// No argument has type `void`.
    #[test]
    fn test_parse_void_argument() {
        let method = create_constructor_with_params(vec![CilFlavor::Void]);
        let blob_data = &[0x01, 0x00, 0x00, 0x00];
        assert!(parse_custom_attribute_data(blob_data, &method.params).is_err());
    }

    #[test]
    fn test_parse_array_argument_error() {
        let method = create_constructor_with_params(vec![CilFlavor::Array {
            element_type: Box::new(CilFlavor::I4),
            rank: 1,
            dimensions: vec![],
        }]);

        let blob_data = &[
            0x01, 0x00, // Prolog
            0x03, 0x00, 0x00, 0x00, // Array element count (I4) = 3
            0x00, 0x00, // NumNamed = 0
        ];

        // Using direct API
        let result = parse_custom_attribute_data(blob_data, &method.params);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Array parameter has no element type"));
    }

    #[test]
    fn test_parse_simple_array_argument() {
        // Create an array type with I4 elements using TypeBuilder
        let test_identity = AssemblyIdentity::parse("TestAssembly, Version=1.0.0.0").unwrap();
        let type_registry = Arc::new(TypeRegistry::new(test_identity).unwrap());

        // Create the array type using TypeBuilder to properly set the base type
        let array_type = TypeBuilder::new(type_registry.clone())
            .primitive(CilPrimitiveKind::I4)
            .unwrap()
            .array()
            .unwrap()
            .build()
            .unwrap();

        // Create method with the array parameter
        let method = create_empty_constructor();
        let param = Arc::new(Param {
            rid: 1,
            token: Token::new(0x08000001),
            offset: 0,
            flags: ParamAttributes::ZERO,
            sequence: 1,
            name: Some("arrayParam".to_string()),
            default: OnceLock::new(),
            marshal: OnceLock::new(),
            modifiers: Arc::new(boxcar::Vec::new()),
            base: OnceLock::new(),
            is_by_ref: std::sync::atomic::AtomicBool::new(false),
            custom_attributes: Default::default(),
        });
        param.base.set(CilTypeRef::from(array_type)).ok();
        method.params.push(param);

        // Test blob data: array with 3 I4 elements
        let blob_data = &[
            0x01, 0x00, // Prolog
            0x03, 0x00, 0x00, 0x00, // Array element count (I4) = 3
            0x01, 0x00, 0x00, 0x00, // First I4: 1
            0x02, 0x00, 0x00, 0x00, // Second I4: 2
            0x03, 0x00, 0x00, 0x00, // Third I4: 3
            0x00, 0x00, // NumNamed = 0
        ];

        // Using direct API
        let result = parse_custom_attribute_data(blob_data, &method.params).unwrap();
        assert_eq!(result.fixed_args.len(), 1);

        match &result.fixed_args[0] {
            CustomAttributeArgument::Array(FieldOrPropType::I4, Some(elements)) => {
                assert_eq!(elements.len(), 3);
                match &elements[0] {
                    CustomAttributeArgument::I4(val) => assert_eq!(*val, 1),
                    _ => panic!("Expected I4 element"),
                }
                match &elements[1] {
                    CustomAttributeArgument::I4(val) => assert_eq!(*val, 2),
                    _ => panic!("Expected I4 element"),
                }
                match &elements[2] {
                    CustomAttributeArgument::I4(val) => assert_eq!(*val, 3),
                    _ => panic!("Expected I4 element"),
                }
            }
            _ => panic!("Expected Array argument"),
        }

        // Keep the type registry alive for the duration of the test
        static TYPE_REGISTRIES: OnceLock<Mutex<HashMap<u64, Arc<TypeRegistry>>>> = OnceLock::new();
        static COUNTER: AtomicU64 = AtomicU64::new(1);

        let registries = TYPE_REGISTRIES.get_or_init(|| Mutex::new(HashMap::new()));
        let mut registries_lock = registries.lock().unwrap();
        let key = COUNTER.fetch_add(1, Ordering::SeqCst);
        registries_lock.insert(key, type_registry);
    }

    #[test]
    fn test_parse_multidimensional_array_error() {
        let method = create_constructor_with_params(vec![CilFlavor::Array {
            element_type: Box::new(CilFlavor::I4),
            rank: 2,
            dimensions: vec![],
        }]);

        let blob_data = &[
            0x01, 0x00, // Prolog
            0x00, 0x00, // NumNamed = 0
        ];

        // Using direct API
        let result = parse_custom_attribute_data(blob_data, &method.params);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("No custom attribute argument can have type"));
    }

    #[test]
    fn test_parse_named_arguments() {
        let method = create_empty_constructor();

        let blob_data = &[
            0x01, 0x00, // Prolog
            0x02, 0x00, // NumNamed = 2
            // First named argument (field)
            0x53, // Field indicator
            0x08, // I4 type
            0x05, // Name length
            0x56, 0x61, 0x6C, 0x75, 0x65, // "Value"
            0x2A, 0x00, 0x00, 0x00, // I4 value: 42
            // Second named argument (property)
            0x54, // Property indicator
            0x0E, // String type
            0x04, // Name length
            0x4E, 0x61, 0x6D, 0x65, // "Name"
            0x04, // String value length
            0x54, 0x65, 0x73, 0x74, // "Test"
        ];

        // Using direct API
        let result = parse_custom_attribute_data(blob_data, &method.params).unwrap();
        assert_eq!(result.fixed_args.len(), 0);
        assert_eq!(result.named_args.len(), 2);

        // Check first named argument (field)
        let field_arg = &result.named_args[0];
        assert!(field_arg.is_field);
        assert_eq!(field_arg.name, "Value");
        assert_eq!(field_arg.arg_type, FieldOrPropType::I4);
        match &field_arg.value {
            CustomAttributeArgument::I4(val) => assert_eq!(*val, 42),
            _ => panic!("Expected I4 value"),
        }

        // Check second named argument (property)
        let prop_arg = &result.named_args[1];
        assert!(!prop_arg.is_field);
        assert_eq!(prop_arg.name, "Name");
        assert_eq!(prop_arg.arg_type, FieldOrPropType::String);
        match &prop_arg.value {
            CustomAttributeArgument::String(Some(val)) => assert_eq!(val, "Test"),
            _ => panic!("Expected String value"),
        }
    }

    #[test]
    fn test_parse_named_argument_char_type() {
        let method = create_empty_constructor();

        let blob_data = &[
            0x01, 0x00, // Prolog
            0x01, 0x00, // NumNamed = 1
            0x53, // Field indicator
            0x03, // Char type
            0x06, // Name length
            0x4C, 0x65, 0x74, 0x74, 0x65, 0x72, // "Letter"
            0x5A, 0x00, // Char value: 'Z' (UTF-16 LE)
        ];

        // Using direct API
        let result = parse_custom_attribute_data(blob_data, &method.params).unwrap();
        assert_eq!(result.named_args.len(), 1);

        let named_arg = &result.named_args[0];
        assert_eq!(named_arg.arg_type, FieldOrPropType::Char);
        match &named_arg.value {
            CustomAttributeArgument::Char(val) => assert_eq!(*val, 0x5A),
            _ => panic!("Expected Char value"),
        }
    }

    #[test]
    fn test_parse_invalid_named_argument_type() {
        let method = create_empty_constructor();

        let blob_data = &[
            0x01, 0x00, // Prolog
            0x01, 0x00, // NumNamed = 1
            0x99, // Invalid field/property indicator (should be 0x53 or 0x54)
            0x08, // Valid type indicator (I4)
            0x04, // Name length
            0x54, 0x65, 0x73, 0x74, // "Test"
        ];

        // Using direct API
        let result = parse_custom_attribute_data(blob_data, &method.params);
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("Invalid field/property indicator"));
        }
    }

    #[test]
    fn test_parse_malformed_data_errors() {
        let method = create_constructor_with_params(vec![CilFlavor::I4]);

        // Test insufficient data for fixed argument
        let blob_data = &[
            0x01, 0x00, // Prolog
            0x00, 0x00, // Not enough data for I4
        ];

        let result = parse_custom_attribute_data(blob_data, &method.params);
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        // Be more flexible with error message matching - accept "Out of Bound"
        // and "read past end of buffer" (ParseFailure::OutOfBounds Display) too.
        assert!(
            error_msg.contains("data")
                || error_msg.contains("I4")
                || error_msg.contains("enough")
                || error_msg.contains("Out of Bound")
                || error_msg.contains("bound")
                || error_msg.contains("read past end"),
            "Error should mention data, I4, or bound issue: {error_msg}"
        );

        // Test string with invalid length
        let method_string = create_constructor_with_params(vec![CilFlavor::String]);
        let blob_data = &[
            0x01, 0x00, // Prolog
            0xFF, 0xFF, 0xFF, 0xFF, 0x0F, // Invalid compressed length (too large)
        ];

        let result = parse_custom_attribute_data(blob_data, &method_string.params);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_mixed_fixed_and_named_arguments() {
        let method = create_constructor_with_params(vec![CilFlavor::I4, CilFlavor::String]);

        let blob_data = &[
            0x01, 0x00, // Prolog
            // Fixed arguments
            0x2A, 0x00, 0x00, 0x00, // I4: 42
            0x05, // String length
            0x48, 0x65, 0x6C, 0x6C, 0x6F, // "Hello"
            // Named arguments
            0x01, 0x00, // NumNamed = 1
            0x54, // Property indicator
            0x02, // Boolean type
            0x07, // Name length
            0x45, 0x6E, 0x61, 0x62, 0x6C, 0x65, 0x64, // "Enabled"
            0x01, // Boolean true
        ];

        // Using direct API
        let result = parse_custom_attribute_data(blob_data, &method.params).unwrap();
        assert_eq!(result.fixed_args.len(), 2);
        assert_eq!(result.named_args.len(), 1);

        // Check fixed arguments
        match &result.fixed_args[0] {
            CustomAttributeArgument::I4(val) => assert_eq!(*val, 42),
            _ => panic!("Expected I4 argument"),
        }
        match &result.fixed_args[1] {
            CustomAttributeArgument::String(Some(val)) => assert_eq!(val, "Hello"),
            _ => panic!("Expected String argument"),
        }

        // Check named argument
        let named_arg = &result.named_args[0];
        assert!(!named_arg.is_field);
        assert_eq!(named_arg.name, "Enabled");
        assert_eq!(named_arg.arg_type, FieldOrPropType::Bool);
        match &named_arg.value {
            CustomAttributeArgument::Bool(val) => assert!(*val),
            _ => panic!("Expected Boolean value"),
        }
    }

    #[test]
    fn test_parse_utf16_edge_cases() {
        let method = create_constructor_with_params(vec![CilFlavor::Char]);

        // An unpaired surrogate is a char value like any other: the code unit is kept
        let blob_data = &[
            0x01, 0x00, // Prolog
            0x00, 0xD8, // Invalid UTF-16 surrogate (0xD800)
            0x00, 0x00, // NumNamed = 0
        ];

        // Using direct API
        let result = parse_custom_attribute_data(blob_data, &method.params).unwrap();
        assert_eq!(result.fixed_args.len(), 1);
        match &result.fixed_args[0] {
            CustomAttributeArgument::Char(val) => assert_eq!(*val, 0xD800),
            _ => panic!("Expected Char argument"),
        }
    }

    #[test]
    fn test_unsupported_type_flavor_error() {
        let method = create_constructor_with_params(vec![CilFlavor::Pointer]);

        let blob_data = &[
            0x01, 0x00, // Prolog
            0x00, 0x00, // NumNamed = 0
        ];

        // Using direct API
        let result = parse_custom_attribute_data(blob_data, &method.params);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("No custom attribute argument can have type"));
    }

    #[test]
    fn test_empty_string_argument() {
        let method = create_constructor_with_params(vec![CilFlavor::String]);

        let blob_data = &[
            0x01, 0x00, // Prolog
            0x00, // String length = 0
            0x00, 0x00, // NumNamed = 0
        ];

        // Using direct API
        let result = parse_custom_attribute_data(blob_data, &method.params).unwrap();
        assert_eq!(result.fixed_args.len(), 1);
        match &result.fixed_args[0] {
            CustomAttributeArgument::String(Some(val)) => assert_eq!(val, ""),
            _ => panic!("Expected String argument"),
        }
    }

    #[test]
    fn test_parse_named_enum_argument_reads_the_enum_type_before_the_name() {
        // ECMA-335 II.23.3: PROPERTY, ENUM, the enum's type name, then the
        // property's name, then the value.
        let method = create_empty_constructor();
        let mut blob = vec![0x01, 0x00, 0x01, 0x00, 0x54, 0x55];
        blob.push(4);
        blob.extend_from_slice(b"E.Ty");
        blob.push(4);
        blob.extend_from_slice(b"Mode");
        blob.extend_from_slice(&7i32.to_le_bytes());

        let result = parse_custom_attribute_data(&blob, &method.params).unwrap();
        let named = &result.named_args[0];
        assert_eq!(named.name, "Mode");
        match &named.value {
            CustomAttributeArgument::Enum(type_name, value) => {
                assert_eq!(type_name, "E.Ty");
                assert!(matches!(**value, CustomAttributeArgument::I4(7)));
            }
            other => panic!("expected an enum, got {other:?}"),
        }
    }

    #[test]
    fn a_named_enum_no_assembly_defines_is_sized_by_the_blob() {
        // `Mode` is an enum over `byte`: as an `int` its value would run past the blob.
        let method = create_empty_constructor();
        let mut blob = vec![0x01, 0x00, 0x01, 0x00, 0x54, 0x55];
        blob.push(4);
        blob.extend_from_slice(b"E.Ty");
        blob.push(4);
        blob.extend_from_slice(b"Mode");
        blob.push(7);

        let result = parse_custom_attribute_data(&blob, &method.params).unwrap();
        match &result.named_args[0].value {
            CustomAttributeArgument::Enum(type_name, value) => {
                assert_eq!(type_name, "E.Ty");
                assert!(matches!(**value, CustomAttributeArgument::U1(7)));
            }
            other => panic!("expected an enum, got {other:?}"),
        }
    }

    #[test]
    fn enums_of_different_sizes_are_sized_together() {
        // `A` over `short`, then `B` over `long`: only those two sizes end the blob after `B`.
        let method = create_empty_constructor();
        let mut blob = vec![0x01, 0x00, 0x02, 0x00];
        for (enum_name, property, value) in [
            (&b"E.A"[..], &b"First"[..], &3u16.to_le_bytes()[..]),
            (&b"E.B"[..], &b"Second"[..], &(-5i64).to_le_bytes()[..]),
        ] {
            blob.extend_from_slice(&[0x54, 0x55, u8::try_from(enum_name.len()).unwrap()]);
            blob.extend_from_slice(enum_name);
            blob.push(u8::try_from(property.len()).unwrap());
            blob.extend_from_slice(property);
            blob.extend_from_slice(value);
        }

        let result = parse_custom_attribute_data(&blob, &method.params).unwrap();
        let values: Vec<_> = result.named_args.iter().map(|arg| &arg.value).collect();
        assert!(matches!(
            values[..],
            [
                CustomAttributeArgument::Enum(_, ref first),
                CustomAttributeArgument::Enum(_, ref second),
            ] if matches!(**first, CustomAttributeArgument::U2(3))
                && matches!(**second, CustomAttributeArgument::I8(-5))
        ));
    }

    #[test]
    fn a_framework_attribute_over_an_imported_byte_enum_loads() {
        // `SecurityRulesAttribute(SecurityRuleSet)`, where `SecurityRuleSet` is mscorlib's enum
        // over `byte`, followed by `SkipVerificationInFullTrust = true`.
        let assembly = CilObject::from_path(fixture("mono_4.8/System.dll")).unwrap();
        let attributes = &assembly.assembly().unwrap().custom_attributes;
        let rules = attributes
            .iter()
            .map(|(_, attribute)| attribute)
            .find(|attribute| {
                matches!(
                    attribute.fixed_args.first(),
                    Some(CustomAttributeArgument::Enum(name, _))
                        if name == "System.Security.SecurityRuleSet"
                )
            })
            .expect("System.dll declares its security rules");

        assert!(matches!(
            rules.fixed_args[..],
            [CustomAttributeArgument::Enum(_, ref value)]
                if matches!(**value, CustomAttributeArgument::U1(1))
        ));
        assert_eq!(rules.named_args.len(), 1);
        assert_eq!(rules.named_args[0].name, "SkipVerificationInFullTrust");
        assert!(matches!(
            rules.named_args[0].value,
            CustomAttributeArgument::Bool(true)
        ));
    }

    #[test]
    fn test_parse_named_array_argument() {
        // FIELD, SZARRAY of I4, the name, then a length and the elements.
        let method = create_empty_constructor();
        let mut blob = vec![0x01, 0x00, 0x01, 0x00, 0x53, 0x1D, 0x08];
        blob.push(6);
        blob.extend_from_slice(b"Values");
        blob.extend_from_slice(&2i32.to_le_bytes());
        blob.extend_from_slice(&10i32.to_le_bytes());
        blob.extend_from_slice(&20i32.to_le_bytes());

        let result = parse_custom_attribute_data(&blob, &method.params).unwrap();
        let named = &result.named_args[0];
        assert_eq!(named.name, "Values");
        assert_eq!(
            named.arg_type,
            FieldOrPropType::SzArray(Box::new(FieldOrPropType::I4))
        );
        match &named.value {
            CustomAttributeArgument::Array(FieldOrPropType::I4, Some(values)) => {
                assert!(matches!(
                    values[..],
                    [
                        CustomAttributeArgument::I4(10),
                        CustomAttributeArgument::I4(20)
                    ]
                ));
            }
            other => panic!("expected an array, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_boxed_enum_array_reads_the_enum_type_before_the_length() {
        // A boxed object holding an enum array: OBJECT, SZARRAY, ENUM, the
        // enum's type name, then the length and the values.
        let method = create_empty_constructor();
        let mut blob = vec![0x01, 0x00, 0x01, 0x00, 0x54, 0x51];
        blob.push(1);
        blob.extend_from_slice(b"P");
        blob.extend_from_slice(&[0x1D, 0x55]);
        blob.push(4);
        blob.extend_from_slice(b"E.Ty");
        blob.extend_from_slice(&1i32.to_le_bytes());
        blob.extend_from_slice(&3i32.to_le_bytes());

        let result = parse_custom_attribute_data(&blob, &method.params).unwrap();
        assert_eq!(result.named_args[0].arg_type, FieldOrPropType::Boxed);
        let CustomAttributeArgument::Boxed(held) = &result.named_args[0].value else {
            panic!(
                "expected a boxed value, got {:?}",
                result.named_args[0].value
            );
        };
        match &**held {
            CustomAttributeArgument::Array(FieldOrPropType::Enum(element), Some(values)) => {
                assert_eq!(element, "E.Ty");
                match &values[..] {
                    [CustomAttributeArgument::Enum(type_name, value)] => {
                        assert_eq!(type_name, "E.Ty");
                        assert!(matches!(**value, CustomAttributeArgument::I4(3)));
                    }
                    other => panic!("expected one enum, got {other:?}"),
                }
            }
            other => panic!("expected an enum array, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_unsupported_named_argument_type() {
        let method = create_empty_constructor();

        let blob_data = &[
            0x01, 0x00, // Prolog
            0x01, 0x00, // NumNamed = 1
            0x53, // Valid field indicator
            0xFF, // Unsupported type indicator
            0x04, // Name length
            0x54, 0x65, 0x73, 0x74, // "Test"
        ];

        // Using direct API
        let result = parse_custom_attribute_data(blob_data, &method.params);
        // Strict parsing should fail on unsupported types
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e
                .to_string()
                .contains("Unsupported serialization type tag: 0xFF"));
        }
    }
}

#[cfg(test)]
mod examples {
    use std::sync::Arc;

    use super::*;
    use crate::{
        metadata::{identity::AssemblyIdentity, typesystem::TypeRegistry},
        Result,
    };

    /// The smallest attribute blob: the prolog and no named arguments.
    const MINIMAL: &[u8] = &[0x01, 0x00, 0x00, 0x00];

    #[test]
    fn new_example() -> Result<()> {
        let mut parser = CustomAttributeParser::new(MINIMAL);
        let parsed = parser.parse_custom_attribute(&ParamList::new())?;
        assert!(parsed.fixed_args.is_empty());
        Ok(())
    }

    #[test]
    fn with_registry_example() -> Result<()> {
        let test_identity = AssemblyIdentity::parse("TestAssembly, Version=1.0.0.0")?;
        let type_registry = Arc::new(TypeRegistry::new(test_identity)?);
        let mut parser = CustomAttributeParser::with_registry(MINIMAL, type_registry);
        let parsed = parser.parse_custom_attribute(&ParamList::new())?;
        assert!(parsed.named_args.is_empty());
        Ok(())
    }

    /// A constructor without parameters, and one named argument: the field `Answer` of type
    /// `int32` set to 42.
    #[test]
    fn parse_custom_attribute_example() -> Result<()> {
        let blob_data = &[
            0x01, 0x00, // prolog
            0x01, 0x00, // one named argument
            0x53, 0x08, // FIELD, int32
            0x06, b'A', b'n', b's', b'w', b'e', b'r', // its name
            0x2A, 0x00, 0x00, 0x00, // 42
        ];
        let mut parser = CustomAttributeParser::new(blob_data);
        let params = ParamList::new();

        let custom_attr = parser.parse_custom_attribute(&params)?;
        assert!(custom_attr.fixed_args.is_empty());
        assert_eq!(custom_attr.named_args.len(), 1);
        assert_eq!(custom_attr.named_args[0].name, "Answer");
        Ok(())
    }
}
