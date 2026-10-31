//! # Param Owned Implementation
//!
//! This module provides the owned variant of Param table entries with resolved
//! references and owned data structures for efficient runtime access.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, OnceLock,
};

use crate::{
    metadata::{
        customattributes::CustomAttributeValueList,
        marshalling::MarshallingInfo,
        signatures::{SignatureMethod, SignatureParameter},
        tables::{ParamAttributes, ParamList},
        token::Token,
        typesystem::{CilPrimitive, CilTypeRef, CilTypeRefList, TypeRegistry, TypeResolver},
    },
    Result,
};

/// Owned representation of a Param table entry with resolved references.
///
/// This structure represents the processed entry from the Param metadata table,
/// which contains information about method parameters including their names, attributes,
/// sequence numbers, and type information. Unlike [`ParamRaw`](crate::metadata::tables::ParamRaw), this version contains
/// resolved references to actual parameter data for efficient runtime access.
///
/// ## Purpose
///
/// The Param table entry provides comprehensive parameter information:
/// - Parameter names for debugging and reflection
/// - Sequence numbers for parameter ordering
/// - Attributes for direction, defaults, and marshalling
/// - Type information for signature construction
/// - Default values and marshalling information when applicable
///
/// ## Parameter Types
///
/// Param entries can represent different types of parameters:
/// - **Input Parameters**: Standard parameters passed to methods
/// - **Output Parameters**: Parameters used to return data from methods
/// - **Optional Parameters**: Parameters that can be omitted in method calls
/// - **Return Type**: Special parameter with sequence 0 representing return type
pub struct Param {
    /// Row identifier within the Param table.
    ///
    /// Unique identifier for this Param entry within the table.
    /// Combined with the table ID, it forms the complete metadata token.
    pub rid: u32,

    /// Metadata token for this Param entry.
    ///
    /// Token in the format 0x08??????, where the high byte 0x08 identifies
    /// the Param table and the low 3 bytes contain the row ID.
    pub token: Token,

    /// Byte offset of this entry in the original metadata stream.
    ///
    /// Used for debugging and low-level metadata inspection.
    /// Points to the start of this entry's data in the file.
    pub offset: usize,

    /// Parameter attributes bitmask according to ECMA-335 §II.23.1.13.
    ///
    /// Defines parameter characteristics including direction (in/out), optional status,
    /// default values, and marshalling information. See [`crate::metadata::tables::ParamAttributes`]
    /// for available flags.
    pub flags: ParamAttributes,

    /// Sequence number defining parameter order.
    ///
    /// - 0: Return type parameter
    /// - 1+: Method parameters in declaration order
    ///   Used for proper parameter binding during method invocation.
    pub sequence: u32,

    /// Parameter name resolved from the string heap.
    ///
    /// Human-readable parameter name for debugging and reflection.
    /// May be None for compiler-generated or unnamed parameters.
    pub name: Option<String>,

    /// Default value for this parameter when `HAS_DEFAULT` flag is set.
    ///
    /// Thread-safe lazy initialization of default values from the Constant table.
    /// Only populated when [`ParamAttributes::HAS_DEFAULT`](crate::metadata::tables::ParamAttributes::HAS_DEFAULT) is set.
    pub default: OnceLock<CilPrimitive>,

    /// Marshalling information for P/Invoke when `HAS_FIELD_MARSHAL` flag is set.
    ///
    /// Thread-safe lazy initialization of marshalling information from the `FieldMarshal` table.
    /// Only populated when [`ParamAttributes::HAS_FIELD_MARSHAL`](crate::metadata::tables::ParamAttributes::HAS_FIELD_MARSHAL) is set.
    pub marshal: OnceLock<MarshallingInfo>,

    /// Custom modifiers applied to this parameter type.
    ///
    /// Thread-safe collection of type modifiers that affect parameter behavior,
    /// such as const, volatile, or custom modifiers for specialized scenarios.
    pub modifiers: CilTypeRefList,

    /// Resolved base type of this parameter.
    ///
    /// Thread-safe lazy initialization of the parameter's type information.
    /// Populated during signature application from method signatures.
    pub base: OnceLock<CilTypeRef>,

    /// Whether the parameter is passed by reference.
    ///
    /// Atomic boolean indicating if the parameter is passed by reference
    /// rather than by value. Updated during signature application.
    pub is_by_ref: AtomicBool,

    /// Custom attributes attached to this parameter.
    ///
    /// Thread-safe collection of custom attributes that provide additional
    /// metadata for this parameter. Populated during custom attribute processing.
    pub custom_attributes: CustomAttributeValueList,
}

impl Param {
    /// Applies a method signature to this parameter, updating type information.
    ///
    /// This method integrates signature information with the parameter definition,
    /// resolving type references and establishing the complete parameter specification.
    /// It handles type resolution, modifier application, and compatibility validation
    /// for shared parameters between methods.
    ///
    /// ## Shared Parameters
    ///
    /// Multiple methods can share the same parameter when they have identical signatures.
    /// This method handles this scenario by checking type compatibility when a parameter
    /// already has a resolved base type.
    ///
    /// ## Arguments
    ///
    /// * `signature` - The signature parameter information to apply
    /// * `types` - The type registry for type lookup and resolution
    /// * `method_param_count` - Optional total parameter count for validation
    ///
    /// ## Returns
    ///
    /// Returns `Ok(())` if the signature is successfully applied.
    ///
    /// ## Errors
    ///
    /// - Parameter sequence exceeds the method parameter count
    /// - Type resolution fails for modifiers or base type
    /// - The base type has already been set with an incompatible type
    /// - Type compatibility validation fails for shared parameters
    /// - Type references become invalid during resolution
    pub fn apply_signature(
        &self,
        signature: &SignatureParameter,
        types: Arc<TypeRegistry>,
        method_param_count: Option<usize>,
    ) -> Result<()> {
        if let Some(param_count) = method_param_count {
            #[allow(clippy::cast_possible_truncation)]
            if self.sequence > param_count as u32 {
                return Err(malformed_error!(
                    "Parameter sequence {} exceeds method parameter count {} for parameter token {}",
                    self.sequence,
                    param_count,
                    self.token.value()
                ));
            }
        }
        self.is_by_ref.store(signature.by_ref, Ordering::Relaxed);

        for modifier in &signature.modifiers {
            match types.get(&modifier.modifier_type) {
                Some(new_mod) => {
                    self.modifiers.push(new_mod.into());
                }
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve modifier type - {}",
                        modifier.modifier_type.value()
                    ))
                }
            }
        }

        let mut resolver = TypeResolver::new(types).with_parent(self.token);
        let resolved_type = resolver.resolve(&signature.base)?;

        // Handle the case where multiple methods share the same parameter
        // This is valid in .NET metadata and happens when methods have identical signatures
        if self.base.set(resolved_type.clone().into()).is_err() {
            if let Some(existing_type_ref) = self.base.get() {
                let existing_type = existing_type_ref.upgrade().ok_or_else(|| {
                    malformed_error!(
                        "Invalid type reference: existing parameter type has been dropped"
                    )
                })?;

                if !resolved_type.is_compatible_with(&existing_type) {
                    return Err(malformed_error!(
                        "Type compatibility error: parameter {} cannot be shared between methods with incompatible types",
                        self.token.value()
                    ));
                }
            }
        }
        Ok(())
    }

    /// The parameters a method signature declares, typed by the signature: the return
    /// parameter (sequence 0) and one per signature parameter (sequence 1 to N).
    ///
    /// Unlike a method's [`crate::metadata::method::Method::params`], which holds the Param
    /// rows the method has, this covers every parameter: ECMA-335 §22.33 makes a Param row
    /// optional, and a parameter without one (no name, no attributes) still takes an
    /// argument. The parameters have no row, so their row, token and name are empty.
    ///
    /// # Errors
    ///
    /// Returns an error if a parameter's type or modifiers cannot be resolved.
    pub fn from_signature(
        signature: &SignatureMethod,
        types: &Arc<TypeRegistry>,
    ) -> Result<ParamList> {
        let params = ParamList::new();
        let param_count = Some(signature.params.len());
        for (sequence, param_signature) in std::iter::once(&signature.return_type)
            .chain(&signature.params)
            .enumerate()
        {
            let param = Arc::new(Param {
                rid: 0,
                token: Token::new(0),
                offset: 0,
                flags: ParamAttributes::ZERO,
                sequence: u32::try_from(sequence)
                    .map_err(|_| malformed_error!("Too many parameters in a method signature"))?,
                name: None,
                default: OnceLock::new(),
                marshal: OnceLock::new(),
                modifiers: Arc::new(boxcar::Vec::new()),
                base: OnceLock::new(),
                is_by_ref: AtomicBool::new(param_signature.by_ref),
                custom_attributes: Default::default(),
            });
            param.apply_signature(param_signature, types.clone(), param_count)?;
            params.push(param);
        }
        Ok(params)
    }
}
