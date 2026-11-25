//! Token format and reference validation for .NET metadata tables.
//!
//! This validator ensures the integrity of token references, RID bounds, and coded indexes
//! across all metadata tables in a .NET assembly. It operates on raw metadata structures
//! to provide foundational validation before type resolution occurs, serving as the highest
//! priority structural validator that must pass before any semantic analysis can proceed.
//!
//! # Architecture
//!
//! The token validation system implements three core validation strategies in sequential order:
//! 1. **Token Reference Validation** - Ensures all token references use valid table types and non-zero RIDs
//! 2. **RID Bounds Validation** - Verifies that RID values do not exceed the 24-bit limit (0x00FFFFFF)
//! 3. **Coded Index Validation** - Validates that coded indexes resolve to appropriate target tables
//!
//! The implementation uses the [`crate::dispatch_table_type`] macro for comprehensive coverage
//! of all metadata table types, ensuring no table is overlooked during validation. This validator
//! runs with the highest priority (200) in the raw validation stage.
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::validators::raw::structure::token::RawTokenValidator`] - Main validator implementation providing comprehensive token validation
//! - [`crate::metadata::validation::validators::raw::structure::token::RawTokenValidator::validate_token_references`] - Validates token references across all tables with token fields
//! - [`crate::metadata::validation::validators::raw::structure::token::RawTokenValidator::validate_rid_bounds`] - Checks RID bounds using comprehensive table dispatch
//! - [`crate::metadata::validation::validators::raw::structure::token::RawTokenValidator::validate_coded_indexes`] - Validates coded index resolution and tag values
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{RawTokenValidator, RawValidator, RawValidationContext};
//!
//! # fn get_context() -> RawValidationContext<'static> { unimplemented!() }
//! let context = get_context();
//! let validator = RawTokenValidator::new();
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
//! This validator returns [`crate::Error::InvalidToken`] for:
//! - Invalid table types in token references (table type not in valid ECMA-335 range)
//! - Zero RID values in token references (except for legitimate null references)
//! - RID values exceeding 24-bit limits (> 0x00FFFFFF)
//! - Invalid coded index tag values (tags outside valid range for coded index type)
//! - Coded indexes pointing to inappropriate target tables (wrong table type for coded index)
//! - Referenced tables not existing in the current assembly
//! - RID values exceeding actual row counts in target tables
//!
//! # Thread Safety
//!
//! All validation operations are read-only and thread-safe. The validator implements [`Send`] + [`Sync`]
//! and can be used concurrently across multiple threads without synchronization as it operates on
//! immutable metadata structures.
//!
//! # Integration
//!
//! This validator integrates with:
//! - raw structure validators - Part of the highest priority structural validation stage
//! - [`crate::metadata::validation::ValidationEngine`] - Orchestrates validator execution with fail-fast behavior
//! - [`crate::metadata::validation::traits::RawValidator`] - Implements the raw validation interface
//! - [`crate::metadata::cilassemblyview::CilAssemblyView`] - Source of metadata tables for validation
//! - [`crate::metadata::validation::context::RawValidationContext`] - Provides validation execution context
//! - [`crate::metadata::validation::ValidationConfig`] - Controls validation execution via enable_structural_validation flag
//!
//! # References
//!
//! - [ECMA-335 II.22](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Metadata tables specification
//! - [ECMA-335 II.24.2.6](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Coded index encoding

use strum::IntoEnumIterator;

use crate::{
    dispatch_table_type,
    metadata::{
        tables::{
            CodedIndex, ConstantRaw, CustomAttributeRaw, CustomDebugInformationRaw,
            DeclSecurityRaw, EventRaw, ExportedTypeRaw, FieldMarshalRaw, GenericParamConstraintRaw,
            GenericParamRaw, ImplMapRaw, InterfaceImplRaw, ManifestResourceRaw, MemberRefRaw,
            MetadataTable, MethodImplRaw, MethodSemanticsRaw, MethodSpecRaw, NestedClassRaw,
            TableId, TypeDefRaw, TypeRefRaw,
        },
        token::Token,
        validation::{
            context::{RawValidationContext, ValidationContext},
            shared::{ReferenceValidator, TokenValidator},
            traits::RawValidator,
        },
    },
    Error, Result,
};

/// Foundation validator for token format, RID bounds, and coded index validation.
///
/// Ensures the structural integrity of all token references, RID values, and coded indexes
/// across metadata tables. This validator operates at the lowest level of metadata validation,
/// providing essential guarantees before higher-level semantic validation can proceed.
///
/// The validator leverages shared validation utilities (shared token and reference validators)
/// to provide comprehensive coverage
/// of all metadata tables using type-safe dispatch mechanisms and validates both direct token
/// references and encoded coded indexes according to ECMA-335 specifications.
///
/// # Thread Safety
///
/// This validator is [`Send`] and [`Sync`] as all validation operations are read-only
/// and operate on immutable metadata structures.
pub struct RawTokenValidator;

impl RawTokenValidator {
    /// Creates a new token validator instance.
    ///
    /// # Returns
    ///
    /// A new [`RawTokenValidator`] ready for validation operations.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Performs comprehensive cross-table reference validation using shared facilities.
    ///
    /// This method leverages shared reference validation utilities to perform
    /// advanced reference analysis including circular dependency detection and reference integrity.
    /// It extracts actual token references from table data rather than making assumptions.
    ///
    /// # Arguments
    ///
    /// * `context` - Raw validation context containing assembly view and scanner
    ///
    /// # Errors
    ///
    /// Returns validation errors if reference integrity issues are detected.
    fn validate_cross_table_references(context: &RawValidationContext) -> Result<()> {
        let assembly_view = context.assembly_view();
        let token_validator = TokenValidator::new(context.reference_scanner());
        let reference_validator = ReferenceValidator::new(context.reference_scanner());

        let mut referenced_tokens = Vec::new();

        if let Some(tables) = assembly_view.tables() {
            if let Some(table) = tables.table::<TypeDefRaw>() {
                for typedef in table {
                    let typedef = typedef?;
                    if typedef.extends.row != 0 {
                        referenced_tokens.push(typedef.extends.token);
                    }
                }
            }

            if let Some(table) = tables.table::<InterfaceImplRaw>() {
                for interface_impl in table {
                    let interface_impl = interface_impl?;
                    token_validator.validate_table_row(TableId::TypeDef, interface_impl.class)?;
                    referenced_tokens.push(interface_impl.interface.token);
                }
            }

            if let Some(table) = tables.table::<MemberRefRaw>() {
                for memberref in table {
                    let memberref = memberref?;
                    referenced_tokens.push(memberref.class.token);
                }
            }

            if let Some(table) = tables.table::<CustomAttributeRaw>() {
                for attr in table {
                    let attr = attr?;
                    referenced_tokens.push(attr.parent.token);
                    referenced_tokens.push(attr.constructor.token);
                }
            }

            if let Some(table) = tables.table::<NestedClassRaw>() {
                for nested in table {
                    let nested = nested?;
                    token_validator.validate_table_row(TableId::TypeDef, nested.nested_class)?;
                    token_validator.validate_table_row(TableId::TypeDef, nested.enclosing_class)?;
                }
            }

            if let Some(table) = tables.table::<GenericParamRaw>() {
                for genparam in table {
                    let genparam = genparam?;
                    referenced_tokens.push(genparam.owner.token);
                }
            }

            if let Some(table) = tables.table::<MethodSpecRaw>() {
                for methodspec in table {
                    let methodspec = methodspec?;
                    referenced_tokens.push(methodspec.method.token);
                }
            }

            if let Some(table) = tables.table::<GenericParamConstraintRaw>() {
                for constraint in table {
                    let constraint = constraint?;
                    token_validator.validate_table_row(TableId::GenericParam, constraint.owner)?;
                    referenced_tokens.push(constraint.constraint.token);
                }
            }

            if let Some(table) = tables.table::<MethodImplRaw>() {
                for method_impl in table {
                    let method_impl = method_impl?;
                    token_validator.validate_table_row(TableId::TypeDef, method_impl.class)?;
                    referenced_tokens.push(method_impl.method_body.token);
                    referenced_tokens.push(method_impl.method_declaration.token);
                }
            }

            if let Some(table) = tables.table::<ConstantRaw>() {
                for constant in table {
                    let constant = constant?;
                    referenced_tokens.push(constant.parent.token);
                }
            }

            if let Some(table) = tables.table::<FieldMarshalRaw>() {
                for marshal in table {
                    let marshal = marshal?;
                    referenced_tokens.push(marshal.parent.token);
                }
            }

            if let Some(table) = tables.table::<DeclSecurityRaw>() {
                for security in table {
                    let security = security?;
                    referenced_tokens.push(security.parent.token);
                }
            }
        }

        reference_validator.validate_token_references(referenced_tokens)?;

        Ok(())
    }

    /// Validates token references across all metadata tables containing token fields.
    ///
    /// Uses shared validation facilities to systematically check all tables that contain
    /// direct token references. This method leverages shared token and reference validators
    /// for comprehensive validation.
    ///
    /// # Arguments
    ///
    /// * `context` - Raw validation context containing assembly view and scanner
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::InvalidToken`] if any token reference is invalid,
    /// including cases where RID values are zero (when not permitted) or reference
    /// non-existent tables or rows.
    fn validate_token_references(context: &RawValidationContext) -> Result<()> {
        let assembly_view = context.assembly_view();
        let token_validator = TokenValidator::new(context.reference_scanner());
        let reference_validator = ReferenceValidator::new(context.reference_scanner());

        if let Some(tables) = assembly_view.tables() {
            if let Some(table) = tables.table::<InterfaceImplRaw>() {
                Self::validate_interfaceimpl_tokens(table, &token_validator, &reference_validator)?;
            }
            if let Some(table) = tables.table::<MemberRefRaw>() {
                Self::validate_memberref_tokens(table, &token_validator, &reference_validator)?;
            }
            if let Some(table) = tables.table::<CustomAttributeRaw>() {
                Self::validate_customattribute_tokens(
                    table,
                    &token_validator,
                    &reference_validator,
                )?;
            }
            if let Some(table) = tables.table::<NestedClassRaw>() {
                Self::validate_nestedclass_tokens(table, &token_validator, &reference_validator)?;
            }
            if let Some(table) = tables.table::<GenericParamRaw>() {
                Self::validate_genericparam_tokens(table, &token_validator, &reference_validator)?;
            }
            if let Some(table) = tables.table::<MethodSpecRaw>() {
                Self::validate_methodspec_tokens(table, &token_validator, &reference_validator)?;
            }
            if let Some(table) = tables.table::<GenericParamConstraintRaw>() {
                Self::validate_genericparamconstraint_tokens(
                    table,
                    &token_validator,
                    &reference_validator,
                )?;
            }
            if let Some(table) = tables.table::<MethodImplRaw>() {
                Self::validate_methodimpl_tokens(table, &token_validator, &reference_validator)?;
            }
            if let Some(table) = tables.table::<ConstantRaw>() {
                Self::validate_constant_tokens(table, &token_validator, &reference_validator)?;
            }
            if let Some(table) = tables.table::<FieldMarshalRaw>() {
                Self::validate_fieldmarshal_tokens(table, &token_validator, &reference_validator)?;
            }
            if let Some(table) = tables.table::<DeclSecurityRaw>() {
                Self::validate_declsecurity_tokens(table, &token_validator, &reference_validator)?;
            }
        }
        Ok(())
    }

    /// Validates RID bounds for all metadata tables using shared validation facilities.
    ///
    /// Uses the [`crate::dispatch_table_type`] macro combined with shared token validation utilities
    /// to validate RID bounds across all possible metadata table types, ensuring no table exceeds
    /// the 24-bit RID limit mandated by the ECMA-335 specification for token encoding.
    ///
    /// # Arguments
    ///
    /// * `context` - Raw validation context containing assembly view and scanner
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::InvalidToken`] if any table has RID count > 0x00FFFFFF,
    /// which would make token encoding impossible using the standard 32-bit token format.
    fn validate_rid_bounds(context: &RawValidationContext) -> Result<()> {
        let assembly_view = context.assembly_view();
        let token_validator = TokenValidator::new(context.reference_scanner());
        if let Some(tables) = assembly_view.tables() {
            for table_id in TableId::iter() {
                let table_type = table_id as u32;
                dispatch_table_type!(table_id, |RawType| {
                    if let Some(table) = tables.table::<RawType>() {
                        let row_count = table.row_count;
                        if row_count > 0x00FF_FFFF {
                            let token_value = (table_type << 24) | row_count;
                            return Err(Error::InvalidToken {
                                token: Token::new(token_value),
                                message: format!(
                                    "{table_id:?} table RID {row_count} exceeds maximum allowed value (0x00FFFFFF)"
                                ),
                            });
                        }

                        for rid in 1..=row_count {
                            token_validator.validate_table_row(table_id, rid)?;
                        }
                    }
                    Ok(()) as Result<()>
                })?;
            }
        }
        Ok(())
    }

    /// Validates coded indexes across all metadata tables containing coded index fields.
    ///
    /// Uses shared validation facilities to validate that coded indexes use valid tag values
    /// and resolve to appropriate target table types according to ECMA-335 coded index specifications.
    /// This implementation leverages shared token validation utilities for comprehensive
    /// coded index validation.
    ///
    /// # Arguments
    ///
    /// * `context` - Raw validation context containing assembly view and scanner
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::InvalidToken`] if any coded index has invalid
    /// tag values or references inappropriate target table types.
    fn validate_coded_indexes(context: &RawValidationContext) -> Result<()> {
        let assembly_view = context.assembly_view();
        let token_validator = TokenValidator::new(context.reference_scanner());
        let reference_validator = ReferenceValidator::new(context.reference_scanner());

        if let Some(tables) = assembly_view.tables() {
            if let Some(table) = tables.table::<TypeDefRaw>() {
                for typedef in table {
                    let typedef = typedef?;
                    Self::validate_coded_index_field(
                        &typedef.extends,
                        &token_validator,
                        &reference_validator,
                    )?;
                }
            }

            if let Some(table) = tables.table::<InterfaceImplRaw>() {
                for interface_impl in table {
                    let interface_impl = interface_impl?;
                    Self::validate_coded_index_field(
                        &interface_impl.interface,
                        &token_validator,
                        &reference_validator,
                    )?;
                }
            }

            if let Some(table) = tables.table::<MemberRefRaw>() {
                for memberref in table {
                    let memberref = memberref?;
                    Self::validate_coded_index_field(
                        &memberref.class,
                        &token_validator,
                        &reference_validator,
                    )?;
                }
            }

            if let Some(table) = tables.table::<CustomAttributeRaw>() {
                for attr in table {
                    let attr = attr?;
                    Self::validate_coded_index_field(
                        &attr.parent,
                        &token_validator,
                        &reference_validator,
                    )?;
                    Self::validate_coded_index_field(
                        &attr.constructor,
                        &token_validator,
                        &reference_validator,
                    )?;
                }
            }

            if let Some(table) = tables.table::<GenericParamRaw>() {
                for genparam in table {
                    let genparam = genparam?;
                    Self::validate_coded_index_field(
                        &genparam.owner,
                        &token_validator,
                        &reference_validator,
                    )?;
                }
            }

            if let Some(table) = tables.table::<MethodSpecRaw>() {
                for methodspec in table {
                    let methodspec = methodspec?;
                    Self::validate_coded_index_field(
                        &methodspec.method,
                        &token_validator,
                        &reference_validator,
                    )?;
                }
            }

            if let Some(table) = tables.table::<GenericParamConstraintRaw>() {
                for constraint in table {
                    let constraint = constraint?;
                    Self::validate_coded_index_field(
                        &constraint.constraint,
                        &token_validator,
                        &reference_validator,
                    )?;
                }
            }

            if let Some(table) = tables.table::<ConstantRaw>() {
                for constant in table {
                    let constant = constant?;
                    Self::validate_coded_index_field(
                        &constant.parent,
                        &token_validator,
                        &reference_validator,
                    )?;
                }
            }

            if let Some(table) = tables.table::<FieldMarshalRaw>() {
                for marshal in table {
                    let marshal = marshal?;
                    Self::validate_coded_index_field(
                        &marshal.parent,
                        &token_validator,
                        &reference_validator,
                    )?;
                }
            }

            if let Some(table) = tables.table::<DeclSecurityRaw>() {
                for security in table {
                    let security = security?;
                    Self::validate_coded_index_field(
                        &security.parent,
                        &token_validator,
                        &reference_validator,
                    )?;
                }
            }
        }
        Ok(())
    }

    /// Validates token references in InterfaceImpl table entries using shared facilities.
    fn validate_interfaceimpl_tokens(
        table: &MetadataTable<InterfaceImplRaw>,
        token_validator: &TokenValidator,
        reference_validator: &ReferenceValidator,
    ) -> Result<()> {
        for interface_impl in table {
            let interface_impl = interface_impl?;
            token_validator.validate_table_row(TableId::TypeDef, interface_impl.class)?;

            let interface_token = interface_impl.interface.token;
            let allowed_tables = interface_impl.interface.ci_type.tables();
            token_validator.validate_typed_token(interface_token, allowed_tables)?;

            reference_validator.validate_token_integrity(interface_token)?;
        }
        Ok(())
    }

    /// Validates token references in MemberRef table entries using shared facilities.
    fn validate_memberref_tokens(
        table: &MetadataTable<MemberRefRaw>,
        token_validator: &TokenValidator,
        reference_validator: &ReferenceValidator,
    ) -> Result<()> {
        for memberref in table {
            let memberref = memberref?;
            let class_token = memberref.class.token;
            let allowed_tables = memberref.class.ci_type.tables();
            token_validator.validate_typed_token(class_token, allowed_tables)?;

            reference_validator.validate_token_integrity(class_token)?;
        }
        Ok(())
    }

    /// Validates token references in CustomAttribute table entries using shared facilities.
    fn validate_customattribute_tokens(
        table: &MetadataTable<CustomAttributeRaw>,
        token_validator: &TokenValidator,
        reference_validator: &ReferenceValidator,
    ) -> Result<()> {
        for attr in table {
            let attr = attr?;
            let parent_token = attr.parent.token;
            token_validator.validate_token_bounds(parent_token)?;
            reference_validator.validate_token_integrity(parent_token)?;

            let constructor_token = attr.constructor.token;
            let allowed_tables = attr.constructor.ci_type.tables();
            token_validator.validate_typed_token(constructor_token, allowed_tables)?;
            reference_validator.validate_token_integrity(constructor_token)?;
        }
        Ok(())
    }

    /// Validates token references in NestedClass table entries using shared facilities.
    fn validate_nestedclass_tokens(
        table: &MetadataTable<NestedClassRaw>,
        token_validator: &TokenValidator,
        reference_validator: &ReferenceValidator,
    ) -> Result<()> {
        for nested in table {
            let nested = nested?;
            token_validator.validate_table_row(TableId::TypeDef, nested.nested_class)?;

            token_validator.validate_table_row(TableId::TypeDef, nested.enclosing_class)?;

            let nested_class_token =
                Token::new(u32::from(TableId::TypeDef.token_type()) << 24 | nested.nested_class);
            let enclosing_class_token =
                Token::new(u32::from(TableId::TypeDef.token_type()) << 24 | nested.enclosing_class);

            reference_validator
                .validate_nested_class_relationship(enclosing_class_token, nested_class_token)?;
        }
        Ok(())
    }

    /// Validates token references in GenericParam table entries using shared facilities.
    fn validate_genericparam_tokens(
        table: &MetadataTable<GenericParamRaw>,
        token_validator: &TokenValidator,
        reference_validator: &ReferenceValidator,
    ) -> Result<()> {
        for genparam in table {
            let genparam = genparam?;
            let owner_token = genparam.owner.token;
            let allowed_tables = genparam.owner.ci_type.tables();
            token_validator.validate_typed_token(owner_token, allowed_tables)?;
            reference_validator.validate_token_integrity(owner_token)?;
        }
        Ok(())
    }

    /// Validates token references in MethodSpec table entries.
    fn validate_methodspec_tokens(
        table: &MetadataTable<MethodSpecRaw>,
        token_validator: &TokenValidator,
        reference_validator: &ReferenceValidator,
    ) -> Result<()> {
        for methodspec in table {
            let methodspec = methodspec?;
            let method_token = methodspec.method.token;
            let allowed_tables = methodspec.method.ci_type.tables();
            token_validator.validate_typed_token(method_token, allowed_tables)?;
            reference_validator.validate_token_integrity(method_token)?;
        }
        Ok(())
    }

    /// Validates token references in GenericParamConstraint table entries.
    fn validate_genericparamconstraint_tokens(
        table: &MetadataTable<GenericParamConstraintRaw>,
        token_validator: &TokenValidator,
        reference_validator: &ReferenceValidator,
    ) -> Result<()> {
        for constraint in table {
            let constraint = constraint?;
            token_validator.validate_table_row(TableId::GenericParam, constraint.owner)?;

            let constraint_token = constraint.constraint.token;
            let allowed_tables = constraint.constraint.ci_type.tables();
            token_validator.validate_typed_token(constraint_token, allowed_tables)?;
            reference_validator.validate_token_integrity(constraint_token)?;
        }
        Ok(())
    }

    /// Validates token references in MethodImpl table entries.
    fn validate_methodimpl_tokens(
        table: &MetadataTable<MethodImplRaw>,
        token_validator: &TokenValidator,
        reference_validator: &ReferenceValidator,
    ) -> Result<()> {
        for method_impl in table {
            let method_impl = method_impl?;
            token_validator.validate_table_row(TableId::TypeDef, method_impl.class)?;

            let body_token = method_impl.method_body.token;
            let allowed_tables = method_impl.method_body.ci_type.tables();
            token_validator.validate_typed_token(body_token, allowed_tables)?;
            reference_validator.validate_token_integrity(body_token)?;

            let declaration_token = method_impl.method_declaration.token;
            let allowed_tables = method_impl.method_declaration.ci_type.tables();
            token_validator.validate_typed_token(declaration_token, allowed_tables)?;
            reference_validator.validate_token_integrity(declaration_token)?;
        }
        Ok(())
    }

    /// Validates token references in Constant table entries.
    fn validate_constant_tokens(
        table: &MetadataTable<ConstantRaw>,
        token_validator: &TokenValidator,
        reference_validator: &ReferenceValidator,
    ) -> Result<()> {
        for constant in table {
            let constant = constant?;
            let parent_token = constant.parent.token;
            token_validator.validate_token_bounds(parent_token)?;
            reference_validator.validate_token_integrity(parent_token)?;
        }
        Ok(())
    }

    /// Validates token references in FieldMarshal table entries.
    fn validate_fieldmarshal_tokens(
        table: &MetadataTable<FieldMarshalRaw>,
        token_validator: &TokenValidator,
        reference_validator: &ReferenceValidator,
    ) -> Result<()> {
        for marshal in table {
            let marshal = marshal?;
            let parent_token = marshal.parent.token;
            let allowed_tables = marshal.parent.ci_type.tables();
            token_validator.validate_typed_token(parent_token, allowed_tables)?;
            reference_validator.validate_token_integrity(parent_token)?;
        }
        Ok(())
    }

    /// Validates token references in DeclSecurity table entries.
    fn validate_declsecurity_tokens(
        table: &MetadataTable<DeclSecurityRaw>,
        token_validator: &TokenValidator,
        reference_validator: &ReferenceValidator,
    ) -> Result<()> {
        for security in table {
            let security = security?;
            let parent_token = security.parent.token;
            let allowed_tables = security.parent.ci_type.tables();
            token_validator.validate_typed_token(parent_token, allowed_tables)?;
            reference_validator.validate_token_integrity(parent_token)?;
        }
        Ok(())
    }

    /// Reports a coded index whose stored tag names no table.
    fn check_coded_index_tag(coded_index: &CodedIndex) -> Result<()> {
        match coded_index.unassigned_tag {
            Some(stored) => Err(Error::InvalidToken {
                token: coded_index.token,
                message: format!(
                    "{:?} coded index stores 0x{stored:X}, whose tag names no table (the runtime reads it as a null reference)",
                    coded_index.ci_type
                ),
            }),
            None => Ok(()),
        }
    }

    /// Checks every coded-index column of every table for a tag that names no table.
    ///
    /// The CLR reads such an index as a null reference, so the reference checks that
    /// follow would report it only as a reference to row 0; this runs first, over every
    /// coded-index column, so that the report names what the file holds.
    fn validate_coded_index_tags(context: &RawValidationContext) -> Result<()> {
        let Some(tables) = context.assembly_view().tables() else {
            return Ok(());
        };
        macro_rules! check_tags {
            ($raw:ty: $($column:ident),+) => {
                if let Some(table) = tables.table::<$raw>() {
                    for row in table {
                        let row = row?;
                        $(Self::check_coded_index_tag(&row.$column)?;)+
                    }
                }
            };
        }
        check_tags!(TypeDefRaw: extends);
        check_tags!(TypeRefRaw: resolution_scope);
        check_tags!(InterfaceImplRaw: interface);
        check_tags!(MemberRefRaw: class);
        check_tags!(ConstantRaw: parent);
        check_tags!(CustomAttributeRaw: parent, constructor);
        check_tags!(FieldMarshalRaw: parent);
        check_tags!(DeclSecurityRaw: parent);
        check_tags!(EventRaw: event_type);
        check_tags!(MethodSemanticsRaw: association);
        check_tags!(MethodImplRaw: method_body, method_declaration);
        check_tags!(ImplMapRaw: member_forwarded);
        check_tags!(ExportedTypeRaw: implementation);
        check_tags!(ManifestResourceRaw: implementation);
        check_tags!(GenericParamRaw: owner);
        check_tags!(MethodSpecRaw: method);
        check_tags!(GenericParamConstraintRaw: constraint);
        check_tags!(CustomDebugInformationRaw: parent);
        Ok(())
    }

    /// Generic helper method to validate any coded index field.
    ///
    /// This method replaces the repetitive validation logic found in table-specific methods
    /// by leveraging the CodedIndex's built-in type information to determine valid tables.
    ///
    /// ## Arguments
    ///
    /// * `coded_index` - The coded index to validate
    /// * `token_validator` - Token validator for checking token format and bounds
    /// * `reference_validator` - Reference validator for checking token integrity
    ///
    /// ## Returns
    ///
    /// Returns `Ok(())` if validation passes, or an error if validation fails.
    fn validate_coded_index_field(
        coded_index: &CodedIndex,
        token_validator: &TokenValidator,
        reference_validator: &ReferenceValidator,
    ) -> Result<()> {
        if coded_index.row != 0 {
            let token = coded_index.token;
            let allowed_tables = coded_index.ci_type.tables();
            token_validator.validate_typed_token(token, allowed_tables)?;
            reference_validator.validate_token_integrity(token)?;
        }
        Ok(())
    }
}

impl RawValidator for RawTokenValidator {
    fn validate_raw(&self, context: &RawValidationContext) -> Result<()> {
        Self::validate_coded_index_tags(context)?;
        Self::validate_token_references(context)?;
        Self::validate_rid_bounds(context)?;
        Self::validate_coded_indexes(context)?;

        if context.config().enable_cross_table_validation {
            Self::validate_cross_table_references(context)?;
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "RawTokenValidator"
    }

    fn priority(&self) -> u32 {
        200
    }

    fn should_run(&self, context: &RawValidationContext) -> bool {
        context.config().enable_structural_validation
    }
}

impl Default for RawTokenValidator {
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
            factories::validation::raw_structure_token::*, get_testfile_wb, validator_test,
            TestAssembly,
        },
    };

    /// Comprehensive test for RawTokenValidator using the centralized test harness.
    ///
    /// This test validates all four core validation rules implemented by RawTokenValidator:
    /// 1. Token Reference Validation (validate_token_references) - Tests MemberRef, GenericParam, MethodSpec
    /// 2. RID Bounds Validation (validate_rid_bounds) - Implicitly tested through RID out-of-bounds errors
    /// 3. Coded Index Validation (validate_coded_indexes) - Tests TypeDef.extends, InterfaceImpl.interface
    /// 4. Cross-Table Reference Validation (validate_cross_table_references) - Tests complex type relationships
    ///
    /// # Test Coverage
    ///
    /// - **Positive Test**: Clean WindowsBase.dll passes all validation rules
    /// - **TypeDef.extends**: Out-of-bounds TypeRef RID triggers InvalidRid
    /// - **MemberRef.class**: Out-of-bounds TypeRef RID triggers InvalidRid
    /// - **GenericParam.owner**: Out-of-bounds TypeDef RID triggers InvalidRid
    /// - **InterfaceImpl.interface**: Out-of-bounds TypeRef RID triggers InvalidRid
    /// - **MethodSpec.method**: Out-of-bounds MethodDef RID triggers InvalidRid
    /// - **Cross-table references**: Valid nested class relationships pass validation
    ///
    /// # Test Configuration
    ///
    /// - enable_structural_validation: true (required for RawTokenValidator)
    /// - enable_cross_table_validation: true (enables cross-table reference checking)
    /// - Other validators disabled for isolation
    ///
    /// # Validation Rules Tested
    ///
    /// The test systematically validates ECMA-335 compliance for:
    /// - Token format validation (24-bit RID + 8-bit table)
    /// - Coded index resolution and bounds checking
    /// - Cross-table reference integrity
    /// - Metadata table consistency
    ///
    /// Each test case targets exactly one validation rule to ensure test isolation
    /// and clear error attribution.
    ///
    /// - Positive: Clean WindowsBase.dll should pass all validation rules
    /// - Negative: Modified assemblies should fail specific validation rules
    /// - Edge cases: Boundary conditions and configuration scenarios
    ///
    /// # ECMA-335 Compliance
    ///
    /// Tests verify compliance with:
    /// - II.22 - Metadata tables specification
    /// - II.24.2.6 - Coded index encoding
    /// - Token format requirements (8-bit table + 24-bit RID)
    #[test]
    fn test_raw_token_validator_comprehensive() -> Result<()> {
        let validator = RawTokenValidator::new();

        validator_test(
            raw_token_validator_file_factory,
            "RawTokenValidator",
            ValidationConfig {
                enable_structural_validation: true,
                enable_cross_table_validation: true,
                ..Default::default()
            },
            |context| validator.validate_raw(context),
        )
    }

    /// Test that RawTokenValidator configuration flags work correctly.
    ///
    /// Verifies that the validator respects enable_structural_validation configuration setting.
    #[test]
    fn test_raw_token_validator_configuration() -> Result<()> {
        let validator = RawTokenValidator::new();

        fn clean_only_factory() -> Result<Vec<TestAssembly>> {
            let clean_testfile = get_testfile_wb();
            Ok(vec![TestAssembly::new(&clean_testfile)])
        }

        let result_disabled = validator_test(
            clean_only_factory,
            "RawTokenValidator",
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

        let result_enabled = validator_test(
            clean_only_factory,
            "RawTokenValidator",
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

    /// Test RawTokenValidator priority and metadata.
    ///
    /// Verifies validator metadata is correct for proper execution ordering.
    #[test]
    fn test_raw_token_validator_metadata() {
        let validator = RawTokenValidator::new();

        assert_eq!(validator.name(), "RawTokenValidator");
        assert_eq!(validator.priority(), 200);

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
