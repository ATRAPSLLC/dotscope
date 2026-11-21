//! Code generation and cleanup for the deobfuscation engine.

use std::collections::BTreeSet;

use crate::{
    cilassembly::{
        extract_local_var_sig_rid, with_method_body, GeneratorConfig, MethodBodyBuilder,
    },
    compiler::{EventKind, SsaCodeGenerator},
    deobfuscation::{context::AnalysisContext, engine::DeobfuscationEngine},
    metadata::{
        tables::{MethodDefRaw, TableDataOwned, TableId},
        token::Token,
        validation::ValidationConfig,
    },
    CilObject, Error, Result,
};

/// What code generation produced, and what cleanup needs to know about it.
pub struct GeneratedCode {
    /// The assembly with the regenerated bodies.
    pub assembly: CilObject,
    /// How many method bodies were regenerated.
    pub regenerated: usize,
    /// The StandAloneSig rows of replaced local signatures, now orphaned.
    pub old_local_signatures: Vec<Token>,
    /// The FieldDef and TypeDef rows created for array data, which cleanup
    /// must not remove.
    pub protected_tokens: BTreeSet<Token>,
    /// The methods whose regenerated code failed, which ship their original
    /// body.
    pub kept_original: BTreeSet<Token>,
}

impl DeobfuscationEngine {
    /// Generates bytecode from optimized SSA and writes it back to the assembly.
    ///
    /// This phase takes the optimized SSA functions from the context and generates
    /// new CIL bytecode for each processed method, replacing the original method bodies.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The assembly to update with new method bodies.
    /// * `ctx` - The analysis context containing canonicalized SSA functions.
    ///
    /// # Returns
    ///
    /// The [`GeneratedCode`]: the updated assembly and what cleanup needs to
    /// know about it.
    ///
    /// # Errors
    ///
    /// Returns an error if code generation or assembly writing fails.
    pub fn generate_code(assembly: CilObject, ctx: &AnalysisContext) -> Result<GeneratedCode> {
        // Skip if no methods were processed
        if ctx.processed_methods.is_empty() {
            return Ok(GeneratedCode {
                assembly,
                regenerated: 0,
                old_local_signatures: Vec::new(),
                protected_tokens: BTreeSet::new(),
                kept_original: BTreeSet::new(),
            });
        }

        let mut cil_assembly = assembly.into_assembly();

        // Generate code for each processed method
        let mut codegen = SsaCodeGenerator::new();
        let mut methods_updated: usize = 0;
        let mut old_sas_tokens = Vec::new();
        let mut kept_original = BTreeSet::new();

        for entry in ctx.processed_methods.iter() {
            let method_token = *entry.value();
            // Note: Dead methods are not removed here during code generation.
            // Dead method removal is handled separately in postprocess cleanup
            // (see cleanup.rs), which uses table_row_remove() with proper RID
            // remapping to maintain metadata integrity.

            // Get the SSA function
            let Some(ssa) = ctx.ssa_functions.get(&method_token) else {
                continue;
            };

            // Generate CIL bytecode from SSA and build method body.
            // If codegen fails for a single method (e.g., EH offset issues
            // after optimization), skip rewriting it and keep the original IL.
            let result = match codegen.compile(&ssa, &mut cil_assembly) {
                Ok(result) => result,
                Err(e) => {
                    log::warn!(
                        "Code generation failed for method {method_token}, \
                         keeping original IL: {e}"
                    );
                    ctx.events
                        .record(EventKind::CodegenRefused)
                        .method(method_token)
                        .message(e.to_string());
                    kept_original.insert(method_token);
                    continue;
                }
            };

            // Warn if exception handlers were lost during code generation.
            // This can happen legitimately when optimization eliminates the
            // guarded try region, making handlers unreachable (e.g., dead code
            // removal, or fake handlers inserted by obfuscators).
            if ssa.has_exception_handlers() && result.exception_handlers.is_empty() {
                log::debug!(
                    "Method {method_token}: all exception handlers lost during code generation"
                );
            }

            // Read existing MethodDef row to get the old RVA
            let rid = method_token.row();
            // closure needed - method reference with turbofish breaks type inference
            #[allow(clippy::redundant_closure_for_method_calls)]
            let existing_row = cil_assembly
                .view()
                .tables()
                .and_then(|t| t.table::<MethodDefRaw>())
                .and_then(|table| table.get(rid).ok().flatten())
                .ok_or_else(|| {
                    Error::ModificationInvalid(format!("MethodDef row {rid} not found"))
                })?;

            // Extract old StandAloneSig RID before replacing the method body.
            // After regeneration, the old SAS entry becomes orphaned because the
            // method now references a new SAS row for its local variable signature.
            let old_rva = existing_row.rva;
            if old_rva != 0 {
                with_method_body(&cil_assembly, old_rva, &mut |data, _| {
                    if let Some(sas_rid) = extract_local_var_sig_rid(data) {
                        old_sas_tokens.push(Token::from_parts(TableId::StandAloneSig, sas_rid));
                    }
                });
            }

            // Build new method body from compilation result
            let (method_body, _local_sig_token) = MethodBodyBuilder::from_compilation(
                result.bytecode,
                result.max_stack,
                result.locals,
                result.exception_handlers,
            )
            .build(&mut cil_assembly)?;

            // Store the method body and get placeholder RVA
            let placeholder_rva = cil_assembly.store_method_body(method_body);

            // Update the MethodDef row's RVA
            let updated_row = MethodDefRaw {
                rid: existing_row.rid,
                token: existing_row.token,
                offset: existing_row.offset,
                rva: placeholder_rva,
                impl_flags: existing_row.impl_flags,
                flags: existing_row.flags,
                name: existing_row.name,
                signature: existing_row.signature,
                param_list: existing_row.param_list,
            };

            cil_assembly.table_row_update(
                TableId::MethodDef,
                rid,
                TableDataOwned::MethodDef(updated_row),
            )?;

            ctx.events
                .record(EventKind::CodeRegenerated)
                .method(method_token);
            methods_updated = methods_updated.saturating_add(1);
        }

        // Finalize array types: creates the parent <PrivateImplementationDetails>
        // TypeDef LAST so it owns all array data fields via field_list ranges.
        codegen.finalize_array_types(&mut cil_assembly)?;

        // Collect protected tokens from codegen before consuming the generator
        let protected_tokens = codegen.protected_tokens().clone();

        if methods_updated == 0 {
            let result = cil_assembly
                .into_cilobject_with(ValidationConfig::analysis(), GeneratorConfig::default())?;
            return Ok(GeneratedCode {
                assembly: result,
                regenerated: 0,
                old_local_signatures: Vec::new(),
                protected_tokens,
                kept_original,
            });
        }

        // Use deobfuscation config to skip original method bodies since we regenerated them
        let result = cil_assembly
            .into_cilobject_with(ValidationConfig::analysis(), GeneratorConfig::default())?;
        Ok(GeneratedCode {
            assembly: result,
            regenerated: methods_updated,
            old_local_signatures: old_sas_tokens,
            protected_tokens,
            kept_original,
        })
    }
}
