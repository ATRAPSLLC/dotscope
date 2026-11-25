//! Sort order validation for the tables the format requires sorted.
//!
//! ECMA-335 §II.22 requires ClassLayout, Constant, CustomAttribute, DeclSecurity, FieldLayout,
//! FieldMarshal, FieldRVA, GenericParam, GenericParamConstraint, ImplMap, InterfaceImpl,
//! MethodImpl, MethodSemantics and NestedClass to be sorted by a key column, and the Portable PDB
//! format adds LocalScope, StateMachineMethod and CustomDebugInformation. The header's `Sorted`
//! bit vector (§II.24.2.6) says which tables are, and the runtime binary-searches those: a row out
//! of place is a row it does not find, so an attribute, an interface or a nested type silently
//! goes missing.
//!
//! [`RawSortOrderValidator`] checks that every table marked sorted is in the order its rows'
//! [`sort_key`](crate::metadata::tables::RowWritable::sort_key) gives, the same key the writer
//! sorts by. It runs when
//! [`enable_sort_order_validation`](crate::metadata::validation::ValidationConfig::enable_sort_order_validation)
//! is set, as it is in every preset but `disabled`.

use strum::IntoEnumIterator;

use crate::{
    dispatch_table_type,
    metadata::{
        tables::{RowWritable, TableId},
        validation::{
            context::{RawValidationContext, ValidationContext},
            shared::err_no_metadata_tables,
            traits::RawValidator,
        },
    },
    Result,
};

/// Checks that every table the header marks sorted is in its sort order.
///
/// The runtime binary-searches the tables marked sorted, so a row out of
/// place is a row it does not find. The order checked is the one each row's
/// [`sort_key`](crate::metadata::tables::RowWritable::sort_key) gives, the
/// same key the writer sorts by.
pub struct RawSortOrderValidator;

impl RawSortOrderValidator {
    /// Creates the validator.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for RawSortOrderValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl RawValidator for RawSortOrderValidator {
    /// # Errors
    ///
    /// Returns an error naming the first row found out of order in a table the
    /// header marks sorted.
    fn validate_raw(&self, context: &RawValidationContext) -> Result<()> {
        let tables = context
            .assembly_view()
            .tables()
            .ok_or_else(err_no_metadata_tables)?;

        for table_id in TableId::iter() {
            if tables.sorted & (1u64 << (table_id as u64)) == 0 {
                continue;
            }
            dispatch_table_type!(table_id, |RawType| {
                if let Some(table) = tables.table::<RawType>() {
                    let mut previous: Option<(u32, (u32, u32))> = None;
                    for row in table.iter().flatten() {
                        let Some(key) = row.sort_key(&tables.info)? else {
                            break;
                        };
                        if let Some((previous_rid, previous_key)) = previous {
                            if key < previous_key {
                                return Err(malformed_error!(
                                    "{:?} is marked sorted, but row {} (key {:?}) belongs before \
                                     row {} (key {:?})",
                                    table_id,
                                    row.rid,
                                    key,
                                    previous_rid,
                                    previous_key
                                ));
                            }
                        }
                        previous = Some((row.rid, key));
                    }
                }
            });
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "RawSortOrderValidator"
    }

    fn priority(&self) -> u32 {
        185
    }

    fn should_run(&self, context: &RawValidationContext) -> bool {
        context.config().enable_sort_order_validation
    }
}
