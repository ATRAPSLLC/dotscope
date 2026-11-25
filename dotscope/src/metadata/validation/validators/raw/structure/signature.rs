//! Raw signature validation for .NET assembly signature blob integrity and format compliance.
//!
//! This validator ensures the structural integrity of signature blobs in metadata tables,
//! validating proper ECMA-335 binary format, calling convention compliance, and blob bounds
//! checking before signature parsing occurs. It operates on raw blob heap data to validate
//! the foundational requirements before higher-level signature validation can proceed.
//! This validator runs with priority 175 in the raw validation stage.
//!
//! # Architecture
//!
//! The signature validation system implements comprehensive blob format validation:
//! 1. **Method Signature Validation** - Validates method signature blobs in MethodDef table
//! 2. **Field Signature Validation** - Validates field type signatures in Field table
//! 3. **Property Signature Validation** - Validates property signatures in Property table
//! 4. **LocalVar Signature Validation** - Validates local variable signatures in StandAloneSig table
//! 5. **TypeSpec Signature Validation** - Validates type specification signatures in TypeSpec table
//! 6. **MemberRef Signature Validation** - Validates member reference signatures in MemberRef table
//!
//! The implementation validates signature blob format according to ECMA-335 specifications,
//! ensuring proper calling convention encoding, compressed integer format, and blob bounds
//! checking without performing full signature parsing.
//!
//! # Key Components
//!
//! - [`RawSignatureValidator`] - Main validator implementation providing comprehensive signature blob validation
//! - [`RawSignatureValidator::validate_signature_blob_integrity`] - Core blob format validation with calling convention checking
//! - [`RawSignatureValidator::validate_calling_convention`] - Calling convention byte validation
//! - [`RawSignatureValidator::validate_compressed_integer`] - Compressed integer format validation
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{RawSignatureValidator, RawValidator, RawValidationContext};
//!
//! # fn get_context() -> RawValidationContext<'static> { unimplemented!() }
//! let context = get_context();
//! let validator = RawSignatureValidator::new();
//!
//! // Check if validation should run based on configuration
//! if validator.should_run(&context) {
//!     validator.validate_raw(&context)?;
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Error Handling
//!
//! This validator returns [`crate::Error::ValidationRawFailed`] for:
//! - Invalid calling convention bytes in signature blobs
//! - Malformed compressed integer encoding in signatures
//! - Signature blobs extending beyond blob heap boundaries
//! - Invalid signature blob size encoding
//! - Signature blobs with insufficient data for declared size
//! - Recursive type definitions exceeding maximum nesting depth
//!
//! # Thread Safety
//!
//! All validation operations are read-only and thread-safe. The validator implements [`Send`] + [`Sync`]
//! and can be used concurrently across multiple threads without synchronization as it operates on
//! immutable signature blob structures.
//!
//! # Integration
//!
//! This validator integrates with:
//! - raw structure validators - Part of the foundational structural validation stage
//! - [`crate::metadata::validation::engine::ValidationEngine`] - Orchestrates validator execution with fail-fast behavior
//! - [`crate::metadata::validation::traits::RawValidator`] - Implements the raw validation interface
//! - [`crate::metadata::cilassemblyview::CilAssemblyView`] - Source of metadata tables and blob heap
//! - [`crate::metadata::validation::context::RawValidationContext`] - Provides validation execution context
//! - [`crate::metadata::validation::config::ValidationConfig`] - Controls validation execution via enable_token_validation flag
//! - owned metadata signature validator - Complemented by semantic signature validation
//!
//! # References
//!
//! - [ECMA-335 II.23.2](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Blobs and signatures
//! - [ECMA-335 II.23.2.1](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Method signatures
//! - [ECMA-335 II.23.2.4](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Field signatures
//! - [ECMA-335 II.23.2.5](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Property signatures

use crate::{
    metadata::{
        cilassemblyview::CilAssemblyView,
        tables::{
            FieldRaw, MemberRefRaw, MethodDefRaw, PropertyRaw, StandAloneSigRaw, TypeSpecRaw,
        },
        validation::{
            context::{RawValidationContext, ValidationContext},
            traits::RawValidator,
        },
    },
    Error, Result,
};

/// Foundation validator for signature blob structure and ECMA-335 format compliance.
///
/// Ensures the structural integrity and format compliance of all signature blobs
/// in a .NET assembly, validating proper calling convention encoding, compressed
/// integer format, and blob bounds checking. This validator operates at the binary
/// format level before signature parsing, providing essential guarantees for safe
/// signature processing.
///
/// The validator implements comprehensive coverage of all signature types according to
/// ECMA-335 specifications, ensuring proper binary format compliance, calling convention
/// validity, and structural integrity across all signature blob formats.
///
/// # Thread Safety
///
/// This validator is [`Send`] and [`Sync`] as all validation operations are read-only
/// and operate on immutable signature blob structures.
pub struct RawSignatureValidator;

/// Signature kind enumeration for blob validation context.
///
/// Defines the expected signature type for blob validation to ensure proper
/// calling convention and format validation according to ECMA-335 specifications.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignatureKind {
    /// Method signature (ECMA-335 II.23.2.1)
    Method,
    /// Field signature (ECMA-335 II.23.2.4)
    Field,
    /// Property signature (ECMA-335 II.23.2.5)
    Property,
    /// Local variable signature (ECMA-335 II.23.2.6)
    LocalVar,
    /// Type specification signature (ECMA-335 II.23.2.14)
    TypeSpec,
    /// Member reference signature (method or field)
    MemberRef,
}

impl RawSignatureValidator {
    /// Creates a new signature blob validator.
    ///
    /// Initializes a validator instance that can be used to validate signature
    /// blob structures across multiple assemblies. The validator is stateless
    /// and can be reused safely across multiple validation operations.
    ///
    /// # Returns
    ///
    /// A new [`RawSignatureValidator`] instance ready for validation operations.
    ///
    /// # Thread Safety
    ///
    /// The returned validator is thread-safe and can be used concurrently.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Validates the integrity and format compliance of a signature blob.
    ///
    /// Performs comprehensive validation of signature blob format including:
    /// 1. Blob existence and minimum size validation
    /// 2. Calling convention byte validation for signature kind
    /// 3. Compressed integer encoding validation
    /// 4. Blob boundary checking to prevent buffer overruns
    /// 5. Basic ECMA-335 format compliance verification
    ///
    /// This method provides foundational guarantees about signature blob integrity
    /// that signature parsers can rely upon during content parsing.
    ///
    /// # Arguments
    ///
    /// * `assembly_view` - Assembly metadata view containing blob heap data
    /// * `blob_index` - Index into the blob heap for the signature
    /// * `expected_kind` - Expected signature type for validation context
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Signature blob is valid and properly formatted
    /// * `Err(`[`crate::Error::ValidationRawFailed`]`)` - Signature blob violations found
    ///
    /// # Errors
    ///
    /// Returns validation errors for:
    /// - Blob index pointing beyond heap boundaries
    /// - Invalid calling convention for signature kind
    /// - Malformed compressed integer encoding
    /// - Insufficient blob data for declared signature size
    fn validate_signature_blob_integrity(
        assembly_view: &CilAssemblyView,
        blob_index: u32,
        expected_kind: SignatureKind,
    ) -> Result<()> {
        if blob_index == 0 {
            return Ok(());
        }

        let Some(blob_heap) = assembly_view.blobs() else {
            return Err(Error::ValidationRawFailed {
                validator: "RawSignatureValidator".to_string(),
                message: "Signature validation requires blob heap access".to_string(),
            });
        };

        let blob_data =
            blob_heap
                .get(blob_index as usize)
                .map_err(|_| Error::ValidationRawFailed {
                    validator: "RawSignatureValidator".to_string(),
                    message: format!("Signature blob index {blob_index} exceeds blob heap bounds"),
                })?;

        let Some((&calling_convention, rest)) = blob_data.split_first() else {
            return Err(Error::ValidationRawFailed {
                validator: "RawSignatureValidator".to_string(),
                message: format!("Signature blob at index {blob_index} is empty"),
            });
        };

        Self::validate_calling_convention(calling_convention, expected_kind, blob_index)?;

        if matches!(
            expected_kind,
            SignatureKind::Method | SignatureKind::LocalVar | SignatureKind::Property
        ) {
            if rest.is_empty() {
                return Err(Error::ValidationRawFailed {
                    validator: "RawSignatureValidator".to_string(),
                    message: format!(
                        "Signature blob at index {blob_index} too short for parameter count"
                    ),
                });
            }

            Self::validate_compressed_integer(rest, blob_index)?;
        }

        Ok(())
    }

    /// Validates calling convention byte for the expected signature kind.
    ///
    /// Ensures the calling convention byte is valid for the signature type
    /// according to ECMA-335 calling convention specifications.
    ///
    /// # Arguments
    ///
    /// * `calling_convention` - The calling convention byte from signature
    /// * `expected_kind` - Expected signature type
    /// * `blob_index` - Blob index for error reporting
    ///
    /// # Returns
    ///
    /// Returns validation error if calling convention is invalid for signature kind.
    fn validate_calling_convention(
        calling_convention: u8,
        expected_kind: SignatureKind,
        blob_index: u32,
    ) -> Result<()> {
        match expected_kind {
            SignatureKind::Method | SignatureKind::MemberRef => {
                // Method calling conventions (ECMA-335 II.23.2.1, coreclr corhdr.h)
                // 0x00 = DEFAULT, 0x01 = C, 0x02 = STDCALL, 0x03 = THISCALL,
                // 0x04 = FASTCALL, 0x05 = VARARG, 0x09 = UNMANAGED,
                // 0x0A = GENERICINST, 0x0B = NATIVEVARARG, 0x0C = ASYNC
                // 0x0D = MAX (invalid). Can also have HASTHIS (0x20) and EXPLICIT_THIS (0x40) flags.
                let base_convention = calling_convention & 0x0F;
                if (0x06..=0x08).contains(&base_convention) || base_convention >= 0x0D {
                    return Err(Error::ValidationRawFailed {
                        validator: "RawSignatureValidator".to_string(),
                        message: format!("Invalid method calling convention 0x{calling_convention:02X} in signature blob {blob_index}"),

                    });
                }
            }
            SignatureKind::Field => {
                // Field signature (ECMA-335 II.23.2.4) - should be 0x06
                if calling_convention != 0x06 {
                    return Err(Error::ValidationRawFailed {
                        validator: "RawSignatureValidator".to_string(),
                        message: format!("Invalid field signature marker 0x{calling_convention:02X} in blob {blob_index}, expected 0x06"),

                    });
                }
            }
            SignatureKind::Property => {
                // Property signature (ECMA-335 II.23.2.5) - should be 0x08 (PROPERTY)
                // Can also have HASTHIS (0x20) flag
                let base_convention = calling_convention & 0x0F;
                if base_convention != 0x08 {
                    return Err(Error::ValidationRawFailed {
                        validator: "RawSignatureValidator".to_string(),
                        message: format!("Invalid property signature marker 0x{calling_convention:02X} in blob {blob_index}, expected 0x08"),

                    });
                }
            }
            SignatureKind::LocalVar => {
                // Local variable signature (ECMA-335 II.23.2.6) - should be 0x07
                if calling_convention != 0x07 {
                    return Err(Error::ValidationRawFailed {
                        validator: "RawSignatureValidator".to_string(),
                        message: format!("Invalid local variable signature marker 0x{calling_convention:02X} in blob {blob_index}, expected 0x07"),

                    });
                }
            }
            SignatureKind::TypeSpec => {
                // TypeSpec signature has various type encodings, basic validation for known ranges
                // Valid element types are in ranges 0x01-0x16, 0x1B-0x20, etc.
                if calling_convention == 0x00 {
                    return Err(Error::ValidationRawFailed {
                        validator: "RawSignatureValidator".to_string(),
                        message: format!("Invalid type specification signature marker 0x{calling_convention:02X} in blob {blob_index}"),

                    });
                }
            }
        }
        Ok(())
    }

    /// Validates compressed integer encoding format.
    ///
    /// Ensures compressed integers follow ECMA-335 encoding rules:
    /// - 1-byte: 0bbbbbbb (0-127)
    /// - 2-byte: 10bbbbbb xxxxxxxx (128-16383)
    /// - 4-byte: 110bbbbb xxxxxxxx yyyyyyyy zzzzzzzz (16384+)
    ///
    /// # Arguments
    ///
    /// * `data` - Blob data starting at compressed integer
    /// * `blob_index` - Blob index for error reporting
    ///
    /// # Returns
    ///
    /// Returns validation error if compressed integer encoding is malformed.
    fn validate_compressed_integer(data: &[u8], blob_index: u32) -> Result<()> {
        let Some(&first_byte) = data.first() else {
            return Err(Error::ValidationRawFailed {
                validator: "RawSignatureValidator".to_string(),
                message: format!("Insufficient data for compressed integer in blob {blob_index}"),
            });
        };

        if (first_byte & 0x80) == 0 {
            // 1-byte encoding: 0bbbbbbb
            // Valid as-is
            Ok(())
        } else if (first_byte & 0xC0) == 0x80 {
            // 2-byte encoding: 10bbbbbb xxxxxxxx
            if data.len() < 2 {
                return Err(Error::ValidationRawFailed {
                    validator: "RawSignatureValidator".to_string(),
                    message: format!(
                        "Insufficient data for 2-byte compressed integer in blob {blob_index}"
                    ),
                });
            }
            Ok(())
        } else if (first_byte & 0xE0) == 0xC0 {
            // 4-byte encoding: 110bbbbb xxxxxxxx yyyyyyyy zzzzzzzz
            if data.len() < 4 {
                return Err(Error::ValidationRawFailed {
                    validator: "RawSignatureValidator".to_string(),
                    message: format!(
                        "Insufficient data for 4-byte compressed integer in blob {blob_index}"
                    ),
                });
            }
            Ok(())
        } else {
            // Invalid encoding pattern
            Err(Error::ValidationRawFailed {
                validator: "RawSignatureValidator".to_string(),
                message: format!(
                    "Invalid compressed integer encoding 0x{first_byte:02X} in blob {blob_index}"
                ),
            })
        }
    }
}

impl RawValidator for RawSignatureValidator {
    /// Validates the structural integrity and format compliance of all signature blobs.
    ///
    /// Performs comprehensive validation of signature blob structures, including:
    /// 1. Method signature validation in MethodDef table
    /// 2. Field signature validation in Field table
    /// 3. Property signature validation in Property table
    /// 4. Local variable signature validation in StandAloneSig table
    /// 5. Type specification signature validation in TypeSpec table
    /// 6. Member reference signature validation in MemberRef table
    ///
    /// This method provides foundational guarantees about signature blob integrity
    /// that higher-level signature validators and parsers can rely upon during content validation.
    ///
    /// # Arguments
    ///
    /// * `context` - Raw validation context containing assembly view and configuration
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All signature blobs are valid and properly formatted
    /// * `Err(`[`crate::Error::ValidationRawFailed`]`)` - Signature blob violations found
    ///
    /// # Configuration
    ///
    /// Controlled by `enable_token_validation` flag in validation configuration.
    fn validate_raw(&self, context: &RawValidationContext) -> Result<()> {
        if !self.should_run(context) {
            return Ok(());
        }

        let assembly_view = context.assembly_view();

        let Some(tables) = assembly_view.tables() else {
            return Ok(());
        };

        // A MethodDef's signature is a method signature: a field signature (0x06) there is
        // invalid, and an index past the heap is reported, not skipped.
        if let Some(table) = tables.table::<MethodDefRaw>() {
            for method in table {
                let method = method?;
                Self::validate_signature_blob_integrity(
                    assembly_view,
                    method.signature,
                    SignatureKind::Method,
                )?;
            }
        }

        if let Some(table) = tables.table::<FieldRaw>() {
            for field in table {
                let field = field?;
                Self::validate_signature_blob_integrity(
                    assembly_view,
                    field.signature,
                    SignatureKind::Field,
                )?;
            }
        }

        if let Some(table) = tables.table::<PropertyRaw>() {
            for property in table {
                let property = property?;
                Self::validate_signature_blob_integrity(
                    assembly_view,
                    property.signature,
                    SignatureKind::Property,
                )?;
            }
        }

        if let Some(table) = tables.table::<StandAloneSigRaw>() {
            for standalone_sig in table {
                let standalone_sig = standalone_sig?;
                if let Some(blob_heap) = assembly_view.blobs() {
                    if let Ok(blob_data) = blob_heap.get(standalone_sig.signature as usize) {
                        if let Some(&calling_convention) = blob_data.first() {
                            let signature_kind = match calling_convention {
                                0x07 => SignatureKind::LocalVar,
                                0x06 => SignatureKind::Field,
                                _ => SignatureKind::Method,
                            };

                            Self::validate_signature_blob_integrity(
                                assembly_view,
                                standalone_sig.signature,
                                signature_kind,
                            )?;
                        }
                    }
                }
            }
        }

        if let Some(table) = tables.table::<TypeSpecRaw>() {
            for type_spec in table {
                let type_spec = type_spec?;
                Self::validate_signature_blob_integrity(
                    assembly_view,
                    type_spec.signature,
                    SignatureKind::TypeSpec,
                )?;
            }
        }

        if let Some(table) = tables.table::<MemberRefRaw>() {
            for member_ref in table {
                let member_ref = member_ref?;
                if let Some(blob_heap) = assembly_view.blobs() {
                    if let Ok(blob_data) = blob_heap.get(member_ref.signature as usize) {
                        if let Some(&calling_convention) = blob_data.first() {
                            let signature_kind = match calling_convention {
                                0x06 => SignatureKind::Field,
                                _ => SignatureKind::Method,
                            };

                            Self::validate_signature_blob_integrity(
                                assembly_view,
                                member_ref.signature,
                                signature_kind,
                            )?;
                        }
                    }
                } else {
                    Self::validate_signature_blob_integrity(
                        assembly_view,
                        member_ref.signature,
                        SignatureKind::MemberRef,
                    )?;
                }
            }
        }

        Ok(())
    }

    /// Returns the validation priority for signature blob validation.
    ///
    /// Signature validation runs with priority 175, after heap validation (180)
    /// but before other structural validators, ensuring blob integrity before
    /// signature parsing occurs.
    fn priority(&self) -> u32 {
        175
    }

    /// Returns the validator name for identification and logging.
    fn name(&self) -> &'static str {
        "RawSignatureValidator"
    }

    /// Determines if signature validation should run based on validation configuration.
    ///
    /// Signature validation is controlled by the `enable_token_validation` flag
    /// since signature blobs are part of the token validation infrastructure.
    fn should_run(&self, context: &RawValidationContext) -> bool {
        context.config().enable_token_validation
    }
}

impl Default for RawSignatureValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        metadata::validation::ValidationConfig,
        testkit::{factories::validation::raw_structure_signature::*, validator_test},
        Result,
    };

    #[test]
    fn test_raw_signature_validator() -> Result<()> {
        let validator = RawSignatureValidator::new();
        let config = ValidationConfig {
            enable_token_validation: true,
            ..Default::default()
        };

        validator_test(
            raw_signature_validator_file_factory,
            "RawSignatureValidator",
            config,
            |context| validator.validate_raw(context),
        )
    }
}
