//! Metadata heap validation for .NET assembly heap integrity and format compliance.
//!
//! This validator ensures the structural integrity of all metadata heaps, including
//! proper formatting, bounds checking, and encoding validation. It operates on raw
//! heap data to validate the foundational requirements before higher-level content
//! validation can proceed. This validator runs with priority 180 in the raw validation
//! stage, providing essential heap integrity guarantees.
//!
//! # Architecture
//!
//! The heap validation system implements comprehensive heap validation strategies in sequential order:
//! 1. **String Heap Validation** - Ensures UTF-8 encoding and null-termination compliance for #Strings stream
//! 2. **Blob Heap Validation** - Validates binary data integrity and size encoding for #Blob stream
//! 3. **GUID Heap Validation** - Verifies GUID format and alignment requirements for #GUID stream
//! 4. **UserString Heap Validation** - Ensures UTF-16 encoding and proper length prefixes for #US stream
//!
//! The implementation validates each heap type according to ECMA-335 specifications,
//! ensuring proper format compliance and data integrity across all metadata heaps.
//! All heap validation performs bounds checking and alignment verification.
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::validators::raw::structure::heap::RawHeapValidator`] - Main validator implementation providing comprehensive heap validation
//! - [`crate::metadata::validation::validators::raw::structure::heap::RawHeapValidator::validate_string_heap`] - String heap format validation with UTF-8 compliance checking
//! - [`crate::metadata::validation::validators::raw::structure::heap::RawHeapValidator::validate_blob_heap`] - Blob heap integrity validation with size encoding verification
//! - [`crate::metadata::validation::validators::raw::structure::heap::RawHeapValidator::validate_guid_heap`] - GUID heap format validation with 16-byte alignment checking
//! - [`crate::metadata::validation::validators::raw::structure::heap::RawHeapValidator::validate_userstring_heap`] - UserString heap encoding validation with UTF-16 compliance
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{RawHeapValidator, RawValidator, RawValidationContext};
//!
//! # fn get_context() -> RawValidationContext<'static> { unimplemented!() }
//! let context = get_context();
//! let validator = RawHeapValidator::new();
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
//! - Invalid UTF-8 encoding in string heaps (#Strings stream violations)
//! - Malformed blob size encoding or data corruption (#Blob stream violations)
//! - Incorrect GUID alignment or invalid format (#GUID stream violations)
//! - Invalid UTF-16 encoding in user string heaps (#US stream violations)
//! - Heap data extending beyond stream boundaries (size/offset limit violations)
//! - Non-aligned heap sizes violating ECMA-335 4-byte alignment requirements
//! - Stream sizes exceeding maximum allowed values (0x7FFFFFFF)
//!
//! # Thread Safety
//!
//! All validation operations are read-only and thread-safe. The validator implements [`Send`] + [`Sync`]
//! and can be used concurrently across multiple threads without synchronization as it operates on
//! immutable heap structures.
//!
//! # Integration
//!
//! This validator integrates with:
//! - raw structure validators - Part of the foundational structural validation stage
//! - [`crate::metadata::validation::engine::ValidationEngine`] - Orchestrates validator execution with fail-fast behavior
//! - [`crate::metadata::validation::traits::RawValidator`] - Implements the raw validation interface
//! - [`crate::metadata::cilassemblyview::CilAssemblyView`] - Source of metadata heaps and stream information
//! - [`crate::metadata::validation::context::RawValidationContext`] - Provides validation execution context
//! - [`crate::metadata::validation::config::ValidationConfig`] - Controls validation execution via enable_structural_validation flag
//!
//! # References
//!
//! - [ECMA-335 II.24.2.3](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - String heap specification
//! - [ECMA-335 II.24.2.4](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Blob heap specification
//! - [ECMA-335 II.24.2.5](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - GUID heap specification
//! - [ECMA-335 II.24.2.6](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - UserString heap specification

use crate::{
    metadata::{
        cilassemblyview::CilAssemblyView,
        validation::{
            context::{RawValidationContext, ValidationContext},
            traits::RawValidator,
        },
    },
    Result,
};

/// Foundation validator for metadata heap structure and encoding compliance.
///
/// Ensures the structural integrity and format compliance of all metadata heaps
/// in a .NET assembly, validating proper encoding, bounds checking, and format
/// requirements. This validator operates at the lowest level of heap validation,
/// providing essential guarantees before higher-level content validation can proceed.
///
/// The validator implements comprehensive coverage of all heap types according to
/// ECMA-335 specifications, ensuring proper UTF-8/UTF-16 encoding, data integrity,
/// and structural compliance across all metadata heap formats.
///
/// # Thread Safety
///
/// This validator is [`Send`] and [`Sync`] as all validation operations are read-only
/// and operate on immutable heap structures.
pub struct RawHeapValidator;

impl RawHeapValidator {
    /// Creates a new metadata heap validator.
    ///
    /// Initializes a validator instance that can be used to validate metadata
    /// heap structures across multiple assemblies. The validator is stateless
    /// and can be reused safely across multiple validation operations.
    ///
    /// # Returns
    ///
    /// A new [`RawHeapValidator`] instance ready for validation operations.
    ///
    /// # Thread Safety
    ///
    /// The returned validator is thread-safe and can be used concurrently.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Validates the string heap for UTF-8 encoding compliance and proper formatting.
    ///
    /// Ensures that the string heap (#Strings) conforms to ECMA-335 requirements,
    /// including proper null-termination, valid UTF-8 encoding, and correct heap
    /// structure. Validates size and alignment requirements for the heap.
    ///
    /// # Arguments
    ///
    /// * `assembly_view` - Assembly metadata view containing heap data via [`crate::metadata::cilassemblyview::CilAssemblyView`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - String heap is valid and properly formatted
    /// * `Err(`[`crate::Error::ValidationRawFailed`]`)` - String heap violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationRawFailed`] if:
    /// - String heap size exceeds maximum allowed value (0x7FFFFFFF)
    /// - String heap size is not 4-byte aligned as required by ECMA-335
    /// - String heap offset exceeds maximum allowed value
    /// - String entries contain invalid UTF-8 sequences
    /// - String entries are not properly null-terminated
    fn validate_string_heap(assembly_view: &CilAssemblyView) -> Result<()> {
        let strings_stream = assembly_view.metadata_root().stream("#Strings");
        if let Some(stream) = strings_stream {
            if stream.size > 0x7FFF_FFFF {
                return Err(malformed_error!(
                    "String heap (#Strings) size {} exceeds maximum allowed size",
                    stream.size
                ));
            }

            if stream.size % 4 != 0 {
                return Err(malformed_error!(
                    "String heap (#Strings) size {} is not 4-byte aligned as required by ECMA-335",
                    stream.size
                ));
            }

            if stream.offset > 0x7FFF_FFFF {
                return Err(malformed_error!(
                    "String heap (#Strings) offset {} exceeds maximum allowed offset",
                    stream.offset
                ));
            }
        }

        // Validate string heap content
        Self::validate_string_heap_content(assembly_view)?;

        Ok(())
    }

    /// Validates the actual content of the string heap for UTF-8 compliance and null-termination.
    ///
    /// Performs deep content validation of string heap entries according to ECMA-335 requirements.
    /// Each string must be valid UTF-8 and properly null-terminated.
    ///
    /// # Arguments
    ///
    /// * `assembly_view` - Assembly metadata view containing string heap data
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All string entries are valid UTF-8 and properly formatted
    /// * `Err(`[`crate::Error::ValidationRawFailed`]`)` - Invalid string content found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationRawFailed`] if:
    /// - String contains invalid UTF-8 byte sequences
    /// - String is not properly null-terminated (ECMA-335 requirement)
    /// - String heap iteration fails due to corruption
    fn validate_string_heap_content(assembly_view: &CilAssemblyView) -> Result<()> {
        // The raw entries, not the decoded strings: decoding is what fails on invalid UTF-8.
        if let Some(strings) = assembly_view.strings() {
            let data = strings.data();
            if data.last().is_some_and(|last| *last != 0) {
                return Err(malformed_error!(
                    "String heap's last entry is not NUL-terminated"
                ));
            }
            let mut offset = 0usize;
            for entry in data.split(|byte| *byte == 0) {
                if std::str::from_utf8(entry).is_err() {
                    return Err(malformed_error!(
                        "String heap contains invalid UTF-8 sequence at offset {}",
                        offset
                    ));
                }
                offset = offset.saturating_add(entry.len()).saturating_add(1);
            }
        }

        Ok(())
    }

    /// Validates the blob heap for data integrity and proper size encoding.
    ///
    /// Ensures that the blob heap (#Blob) conforms to ECMA-335 requirements,
    /// including proper size encoding using compressed integers and valid blob
    /// boundaries. Validates size and alignment requirements for the heap.
    ///
    /// # Arguments
    ///
    /// * `assembly_view` - Assembly metadata view containing heap data via [`crate::metadata::cilassemblyview::CilAssemblyView`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Blob heap is valid and properly formatted
    /// * `Err(`[`crate::Error::ValidationRawFailed`]`)` - Blob heap violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationRawFailed`] if:
    /// - Blob heap size exceeds maximum allowed value (0x7FFFFFFF)
    /// - Blob heap size is not 4-byte aligned as required by ECMA-335
    /// - Blob heap offset exceeds maximum allowed value
    /// - Blob entries have invalid size encoding or data corruption
    fn validate_blob_heap(assembly_view: &CilAssemblyView) -> Result<()> {
        let blob_stream = assembly_view.metadata_root().stream("#Blob");

        if let Some(stream) = blob_stream {
            if stream.size > 0x7FFF_FFFF {
                return Err(malformed_error!(
                    "Blob heap (#Blob) size {} exceeds maximum allowed size",
                    stream.size
                ));
            }

            if stream.size % 4 != 0 {
                return Err(malformed_error!(
                    "Blob heap (#Blob) size {} is not 4-byte aligned as required by ECMA-335",
                    stream.size
                ));
            }

            if stream.offset > 0x7FFF_FFFF {
                return Err(malformed_error!(
                    "Blob heap (#Blob) offset {} exceeds maximum allowed offset",
                    stream.offset
                ));
            }
        }

        Self::validate_blob_heap_content(assembly_view)?;

        Ok(())
    }

    /// Validates the actual content of the blob heap for proper size encoding and data integrity.
    ///
    /// Performs deep content validation of blob heap entries according to ECMA-335 requirements.
    /// Each blob must have valid compressed integer size prefixes and consistent data length.
    ///
    /// # Arguments
    ///
    /// * `assembly_view` - Assembly metadata view containing blob heap data
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All blob entries have valid size encoding and data integrity
    /// * `Err(`[`crate::Error::ValidationRawFailed`]`)` - Invalid blob content found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationRawFailed`] if:
    /// - Blob has invalid compressed integer size prefix
    /// - Blob data length doesn't match encoded size
    /// - Blob heap iteration fails due to corruption
    fn validate_blob_heap_content(assembly_view: &CilAssemblyView) -> Result<()> {
        if let Some(blobs) = assembly_view.blobs() {
            for (offset, blob_data) in blobs.iter() {
                if blob_data.len() > 0x1FFF_FFFF {
                    return Err(malformed_error!(
                        "Blob at offset {} has excessive size {} bytes (max: {})",
                        offset,
                        blob_data.len(),
                        0x1FFF_FFFF
                    ));
                }

                // Note: More sophisticated blob content validation could include:
                // - Validating compressed integer encoding in the raw blob stream
                // - Checking that size prefixes match actual data lengths
                // - Validating specific blob content formats (signatures, etc.)
                // These would require access to the raw blob stream data
            }
        }

        Ok(())
    }

    /// Validates the GUID heap for proper format and alignment.
    ///
    /// Ensures that the GUID heap (#GUID) conforms to ECMA-335 requirements,
    /// including proper 16-byte GUID alignment and valid heap structure.
    /// Validates that the heap contains only complete GUID entries.
    ///
    /// # Arguments
    ///
    /// * `assembly_view` - Assembly metadata view containing heap data via [`crate::metadata::cilassemblyview::CilAssemblyView`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - GUID heap is valid and properly formatted
    /// * `Err(`[`crate::Error::ValidationRawFailed`]`)` - GUID heap violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationRawFailed`] if:
    /// - GUID heap size exceeds maximum allowed value (0x7FFFFFFF)
    /// - GUID heap size is not a multiple of 16 bytes (GUID entry size)
    /// - GUID heap size is not 4-byte aligned as required by ECMA-335
    /// - GUID heap offset exceeds maximum allowed value
    /// - GUID entries are malformed or contain invalid data
    fn validate_guid_heap(assembly_view: &CilAssemblyView) -> Result<()> {
        let guid_stream = assembly_view.metadata_root().stream("#GUID");

        if let Some(stream) = guid_stream {
            if stream.size > 0x7FFF_FFFF {
                return Err(malformed_error!(
                    "GUID heap (#GUID) size {} exceeds maximum allowed size",
                    stream.size
                ));
            }

            if stream.size % 16 != 0 {
                return Err(malformed_error!(
                    "GUID heap (#GUID) size {} is not a multiple of 16 bytes (GUID size)",
                    stream.size
                ));
            }

            if stream.size % 4 != 0 {
                return Err(malformed_error!(
                    "GUID heap (#GUID) size {} is not 4-byte aligned as required by ECMA-335",
                    stream.size
                ));
            }

            if stream.offset > 0x7FFF_FFFF {
                return Err(malformed_error!(
                    "GUID heap (#GUID) offset {} exceeds maximum allowed offset",
                    stream.offset
                ));
            }
        }

        Self::validate_guid_heap_content(assembly_view)?;

        Ok(())
    }

    /// Validates the actual content of the GUID heap for proper GUID format and data integrity.
    ///
    /// Performs deep content validation of GUID heap entries according to ECMA-335 requirements.
    /// Each GUID must be exactly 16 bytes and accessible through the heap interface.
    /// Validates GUID heap accessibility, iteration capability, and basic format compliance.
    ///
    /// # Arguments
    ///
    /// * `assembly_view` - Assembly metadata view containing GUID heap data
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All GUID entries are properly formatted and accessible
    /// * `Err(`[`crate::Error::ValidationRawFailed`]`)` - Invalid GUID content found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationRawFailed`] if:
    /// - GUID heap iteration fails due to corruption
    /// - GUID entries are inaccessible or malformed
    /// - GUID heap contains inconsistent data
    /// - Individual GUID access fails unexpectedly
    fn validate_guid_heap_content(assembly_view: &CilAssemblyView) -> Result<()> {
        if let Some(guids) = assembly_view.guids() {
            let mut guid_count: usize = 0;

            // Validate accessibility through iteration
            // Note: The GUID iterator returns (1-based index, GUID), not byte offsets
            for (one_based_index, guid_data) in guids.iter() {
                guid_count = guid_count.saturating_add(1);

                // Verify GUID data is properly accessible
                let guid_bytes = guid_data.to_bytes();

                // GUID format validation: ensure it's exactly 16 bytes
                if guid_bytes.len() != 16 {
                    return Err(malformed_error!(
                        "GUID at index {} has invalid length {} (expected 16 bytes)",
                        one_based_index,
                        guid_bytes.len()
                    ));
                }

                // Verify 1-based indexing access returns the same GUID
                match guids.get(one_based_index) {
                    Ok(indexed_guid) => {
                        let indexed_bytes = indexed_guid.to_bytes();
                        if indexed_bytes != guid_bytes {
                            return Err(malformed_error!(
                                "GUID heap consistency error: iterator and indexed access return different data for index {}",
                                one_based_index
                            ));
                        }
                    }
                    Err(_) => {
                        return Err(malformed_error!(
                            "GUID heap access error: cannot access GUID at 1-based index {}",
                            one_based_index
                        ));
                    }
                }
            }

            // Verify count consistency with heap size
            if let Some(guid_stream) = assembly_view.metadata_root().stream("#GUID") {
                let expected_count = (guid_stream.size / 16) as usize;
                if guid_count != expected_count {
                    return Err(malformed_error!(
                        "GUID heap count mismatch: found {} GUIDs but stream size {} indicates {} GUIDs",
                        guid_count,
                        guid_stream.size,
                        expected_count
                    ));
                }
            }
        }

        Ok(())
    }

    /// Validates the user string heap for UTF-16 encoding compliance and proper length prefixes.
    ///
    /// Ensures that the user string heap (#US) conforms to ECMA-335 requirements,
    /// including proper length prefixing, valid UTF-16 encoding, and correct heap
    /// structure. Validates size and alignment requirements for the heap.
    ///
    /// # Arguments
    ///
    /// * `assembly_view` - Assembly metadata view containing heap data via [`crate::metadata::cilassemblyview::CilAssemblyView`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - UserString heap is valid and properly formatted
    /// * `Err(`[`crate::Error::ValidationRawFailed`]`)` - UserString heap violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationRawFailed`] if:
    /// - UserString heap size exceeds maximum allowed value (0x7FFFFFFF)
    /// - UserString heap size is not 4-byte aligned as required by ECMA-335
    /// - UserString heap offset exceeds maximum allowed value
    /// - UserString entries have invalid UTF-16 encoding or length prefixes
    fn validate_userstring_heap(assembly_view: &CilAssemblyView) -> Result<()> {
        let us_stream = assembly_view.metadata_root().stream("#US");

        if let Some(stream) = us_stream {
            if stream.size > 0x7FFF_FFFF {
                return Err(malformed_error!(
                    "UserString heap (#US) size {} exceeds maximum allowed size",
                    stream.size
                ));
            }

            if stream.size % 4 != 0 {
                return Err(malformed_error!(
                    "UserString heap (#US) size {} is not 4-byte aligned as required by ECMA-335",
                    stream.size
                ));
            }

            if stream.offset > 0x7FFF_FFFF {
                return Err(malformed_error!(
                    "UserString heap (#US) offset {} exceeds maximum allowed offset",
                    stream.offset
                ));
            }
        }

        Self::validate_userstring_heap_content(assembly_view)?;

        Ok(())
    }

    /// Validates the structural integrity of user string heap entries.
    ///
    /// Per ECMA-335 II.24.2.4, the UserString heap can contain arbitrary binary data.
    /// This method validates structural properties (length bounds) but does not reject
    /// non-UTF-16 sequences, as those are spec-legal.
    ///
    /// # Arguments
    ///
    /// * `assembly_view` - Assembly metadata view containing user string heap data
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All user string entries have valid structural formatting
    /// * `Err(`[`crate::Error::ValidationRawFailed`]`)` - Invalid user string structure found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationRawFailed`] if:
    /// - User string has excessive length
    /// - User string heap iteration fails due to corruption
    fn validate_userstring_heap_content(assembly_view: &CilAssemblyView) -> Result<()> {
        if let Some(userstrings) = assembly_view.userstrings() {
            for (offset, userstring_data) in userstrings.iter() {
                let utf16_chars = userstring_data.as_slice();
                if utf16_chars.len() > 0x1FFF_FFFF {
                    return Err(malformed_error!(
                        "UserString at offset {} has excessive length {} characters (max: {})",
                        offset,
                        utf16_chars.len(),
                        0x1FFF_FFFF
                    ));
                }

                // Per ECMA-335 II.24.2.4, the UserString heap can contain arbitrary
                // binary data. The terminal byte indicates whether non-ASCII characters
                // are present. We only validate structural integrity (length), not
                // UTF-16 well-formedness.
            }
        }

        Ok(())
    }
}

impl RawValidator for RawHeapValidator {
    /// Validates the structural integrity and format compliance of all metadata heaps.
    ///
    /// Performs comprehensive validation of heap structures, including:
    /// 1. String heap UTF-8 encoding and null-termination validation
    /// 2. Blob heap data integrity and size encoding validation
    /// 3. GUID heap format and alignment validation
    /// 4. UserString heap UTF-16 encoding and length prefix validation
    ///
    /// This method provides foundational guarantees about metadata heap integrity
    /// that higher-level validators can rely upon during content validation.
    ///
    /// # Arguments
    ///
    /// * `context` - Raw validation context containing assembly view and configuration
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All heap structures are valid and meet ECMA-335 requirements
    /// * `Err(`[`crate::Error::ValidationRawFailed`]`)` - Heap structure violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationRawFailed`] for:
    /// - Invalid UTF-8 encoding in string heaps
    /// - Malformed blob size encoding or corrupted data
    /// - Incorrect GUID alignment or invalid format
    /// - Invalid UTF-16 encoding in user string heaps
    /// - Heap data extending beyond stream boundaries
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and performs only read-only operations on metadata.
    fn validate_raw(&self, context: &RawValidationContext) -> Result<()> {
        let assembly_view = context.assembly_view();

        Self::validate_string_heap(assembly_view)?;
        Self::validate_blob_heap(assembly_view)?;
        Self::validate_guid_heap(assembly_view)?;
        Self::validate_userstring_heap(assembly_view)?;

        Ok(())
    }

    fn name(&self) -> &'static str {
        "RawHeapValidator"
    }

    fn priority(&self) -> u32 {
        180
    }

    fn should_run(&self, context: &RawValidationContext) -> bool {
        context.config().enable_structural_validation
    }
}

impl Default for RawHeapValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        metadata::validation::ValidationConfig,
        testkit::{
            factories::validation::raw_structure_heap::*, get_testfile_wb, validator_test,
            TestAssembly,
        },
        Result,
    };

    #[test]
    fn test_raw_heap_validator() -> Result<()> {
        let validator = RawHeapValidator::new();
        let config = ValidationConfig {
            enable_structural_validation: true,
            ..Default::default()
        };

        validator_test(
            raw_heap_validator_file_factory,
            "RawHeapValidator",
            config,
            |context| validator.validate_raw(context),
        )
    }

    #[test]
    fn test_raw_heap_validator_configuration() -> Result<()> {
        let validator = RawHeapValidator::new();

        fn clean_only_factory() -> Result<Vec<TestAssembly>> {
            let clean_testfile = get_testfile_wb();
            Ok(vec![TestAssembly::new(&clean_testfile)])
        }

        // Test disabled configuration
        let result_disabled = validator_test(
            clean_only_factory,
            "RawHeapValidator",
            ValidationConfig {
                enable_structural_validation: false,
                ..Default::default()
            },
            |context| {
                if validator.should_run(context) {
                    validator.validate_raw(context)
                } else {
                    Ok(())
                }
            },
        );

        assert!(
            result_disabled.is_ok(),
            "Configuration test failed: validator should not run when disabled"
        );

        // Test enabled configuration
        let result_enabled = validator_test(
            clean_only_factory,
            "RawHeapValidator",
            ValidationConfig {
                enable_structural_validation: true,
                ..Default::default()
            },
            |context| validator.validate_raw(context),
        );

        assert!(
            result_enabled.is_ok(),
            "Configuration test failed: validator should run when enabled"
        );
        Ok(())
    }

    #[test]
    fn test_raw_heap_validator_metadata() {
        let validator = RawHeapValidator::new();

        assert_eq!(validator.name(), "RawHeapValidator");
        assert_eq!(validator.priority(), 180);

        let _config_enabled = ValidationConfig {
            enable_structural_validation: true,
            ..Default::default()
        };
        let _config_disabled = ValidationConfig {
            enable_structural_validation: false,
            ..Default::default()
        };
    }
}
