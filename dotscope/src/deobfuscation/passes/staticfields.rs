//! Generic static field resolution pass.
//!
//! Replaces `LoadStaticField` operations referencing obfuscator container fields
//! with their resolved constant values obtained via emulation. This is the shared
//! implementation used by multiple obfuscator-specific techniques (JIEJIE.NET
//! int32 containers, string encryption classes, etc.).
//!
//! # Algorithm
//!
//! 1. On first invocation, fork the emulation template pool (with optional
//!    targeted `.cctor` warmup) and read all container field values from the
//!    emulator's static field table
//! 2. Convert each raw [`EmValue`] to an SSA [`ConstValue`] via the caller-provided
//!    value extractor
//! 3. For each method, scan for `LoadStaticField { field }` where the field token
//!    is in the resolved set
//! 4. Replace each match with `Const { dest, value }`
//!
//! # Value Extraction
//!
//! The pass is parameterized by a [`FieldValueExtractor`] that converts raw
//! emulator values to SSA constants. This keeps the pass generic - techniques
//! provide extractors for their specific value types (I32, String, etc.)
//! without modifying the pass itself.
//!
//! # Example
//!
//! ```text
//! // Before (JIEJIE.NET int32 container):
//! v5 = LoadStaticField(_Int32ValueContainer::_6_1)
//!
//! // After (resolved value = 1):
//! v5 = Const(I32(1))
//!
//! // Before (JIEJIE.NET string class):
//! v3 = LoadStaticField(_Strings78::_5)
//!
//! // After (decrypted string):
//! v3 = Const(DecryptedString("Hello, World!"))
//! ```

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use log::{debug, info, warn};

use crate::{
    analysis::{CilTarget, ConstValue, MethodRef, SsaFunction, SsaOp, SsaVarId},
    compiler::{CompilerContext, EventKind, ModificationScope, PassCapability, SsaPass},
    deobfuscation::{EmulationTemplatePool, ProcessCell},
    emulation::{EmValue, EmulationProcess},
    metadata::token::Token,
    CilObject, Error,
};

/// Extracts an SSA [`ConstValue`] from a raw emulator value.
///
/// Implementations convert obfuscator-specific field types (I32, String, etc.)
/// into the appropriate SSA constant representation. The extractor receives the
/// emulation process (for heap access) and the raw field value.
pub trait FieldValueExtractor: Send + Sync {
    /// Attempts to convert a raw emulator value to an SSA constant.
    ///
    /// # Arguments
    ///
    /// * `process` - The emulation process, for heap/string lookups.
    /// * `field_token` - Token of the field being resolved (for diagnostics).
    /// * `value` - The raw emulator value read from the static field table.
    ///
    /// # Returns
    ///
    /// `Some(ConstValue)` if the value was successfully converted, `None` to skip.
    fn extract(
        &self,
        process: &EmulationProcess,
        field_token: Token,
        value: &EmValue,
    ) -> Option<ConstValue>;

    /// Returns the [`EventKind`] to record for each successful replacement.
    fn event_kind(&self) -> EventKind;

    /// Returns a human-readable label for log messages (e.g., `"Int32ValueContainer"`).
    fn label(&self) -> &str;
}

/// Extracts `I32` constants from emulator static fields.
///
/// Accepts [`EmValue::I32`] values, logging unexpected types at debug level.
/// Used by JIEJIE.NET's `Int32ValueContainer` resolution.
pub struct I32Extractor;

impl FieldValueExtractor for I32Extractor {
    fn extract(
        &self,
        _process: &EmulationProcess,
        field_token: Token,
        value: &EmValue,
    ) -> Option<ConstValue> {
        match value {
            EmValue::I32(val) => Some(ConstValue::I32(*val)),
            other => {
                debug!(
                    "Int32ValueContainer: field 0x{:08X} has unexpected type {:?}",
                    field_token.value(),
                    other
                );
                None
            }
        }
    }

    fn event_kind(&self) -> EventKind {
        EventKind::ConstantFolded
    }

    fn label(&self) -> &str {
        "Int32ValueContainer"
    }
}

/// Extracts `I64` constants from emulator static fields.
///
/// Accepts [`EmValue::I64`] values directly, and widens [`EmValue::I32`] values
/// to `i64` for containers where the runtime stores narrower values in a field
/// declared as `int64`. Logs unexpected types at debug level.
pub struct I64Extractor;

impl FieldValueExtractor for I64Extractor {
    fn extract(
        &self,
        _process: &EmulationProcess,
        field_token: Token,
        value: &EmValue,
    ) -> Option<ConstValue> {
        match value {
            EmValue::I64(val) => Some(ConstValue::I64(*val)),
            // I32 values in a container declared as I64 - widen
            EmValue::I32(val) => Some(ConstValue::I64(i64::from(*val))),
            other => {
                debug!(
                    "Int64ValueContainer: field 0x{:08X} has unexpected type {:?}",
                    field_token.value(),
                    other
                );
                None
            }
        }
    }

    fn event_kind(&self) -> EventKind {
        EventKind::ConstantFolded
    }

    fn label(&self) -> &str {
        "Int64ValueContainer"
    }
}

/// Extracts `F64` (double-precision float) constants from emulator static fields.
///
/// Accepts [`EmValue::F64`] directly, and widens [`EmValue::F32`] to `f64` for
/// containers that mix single- and double-precision values. Logs unexpected types
/// at debug level.
pub struct F64Extractor;

impl FieldValueExtractor for F64Extractor {
    fn extract(
        &self,
        _process: &EmulationProcess,
        field_token: Token,
        value: &EmValue,
    ) -> Option<ConstValue> {
        match value {
            EmValue::F64(val) => Some(ConstValue::from(*val)),
            EmValue::F32(val) => Some(ConstValue::from(f64::from(*val))),
            other => {
                debug!(
                    "Float64ValueContainer: field 0x{:08X} has unexpected type {:?}",
                    field_token.value(),
                    other
                );
                None
            }
        }
    }

    fn event_kind(&self) -> EventKind {
        EventKind::ConstantFolded
    }

    fn label(&self) -> &str {
        "Float64ValueContainer"
    }
}

/// Extracts decrypted strings from emulator static fields.
///
/// Handles [`EmValue::ObjectRef`] (heap-allocated string) by looking up the
/// string content in the emulation address space, and [`EmValue::Null`]
/// (field initialized to null) by producing an empty string. Logs unexpected
/// types and heap lookup failures at debug level.
pub struct StringExtractor;

impl FieldValueExtractor for StringExtractor {
    fn extract(
        &self,
        process: &EmulationProcess,
        field_token: Token,
        value: &EmValue,
    ) -> Option<ConstValue> {
        match value {
            EmValue::ObjectRef(heap_ref) => match process.address_space().get_string(*heap_ref) {
                Ok(s) => Some(ConstValue::DecryptedString(s.to_string().into_boxed_str())),
                Err(e) => {
                    debug!(
                        "StringField: field 0x{:08X} has ObjectRef but get_string failed: {}",
                        field_token.value(),
                        e
                    );
                    None
                }
            },
            EmValue::Null => {
                // Null string - field initialized to null (rare but valid)
                Some(ConstValue::DecryptedString(Box::from("")))
            }
            other => {
                debug!(
                    "StringField: field 0x{:08X} has unexpected type {:?}",
                    field_token.value(),
                    other
                );
                None
            }
        }
    }

    fn event_kind(&self) -> EventKind {
        EventKind::StringDecrypted
    }

    fn label(&self) -> &str {
        "StringField"
    }
}

/// Generic SSA pass that resolves static field loads to constants via emulation.
///
/// Created by obfuscator-specific techniques after detection identifies the
/// container class and its fields. The container's `.cctor` is typically
/// registered as a warmup method so the emulation template pool runs it before
/// any forks, populating all container fields with their computed values.
///
/// The pass is parameterized by a [`FieldValueExtractor`] that converts raw
/// emulator values to SSA constants, making it reusable across different
/// obfuscator container types (int32, string, etc.).
pub struct StaticFieldResolutionPass {
    /// Display name for this pass instance.
    pass_name: &'static str,
    /// Display description for this pass instance.
    pass_description: &'static str,
    /// Lazily-initialized emulation process (pool fork + optional targeted warmup).
    /// Stored for `finalize()` cleanup to release the `Arc<CilObject>` reference.
    lazy_process: ProcessCell,
    /// Shared emulation template pool for O(1) forks.
    template_pool: Arc<EmulationTemplatePool>,
    /// Container field tokens to resolve.
    field_tokens: Vec<Token>,
    /// Optional token of the container .cctor method for targeted warmup.
    /// When `Some`, the pass forks with targeted warmup for this method.
    /// When `None`, a plain fork is used (warmup assumed via registered warmup methods).
    cctor_token: Option<Token>,
    /// Resolved field values: field_token -> ConstValue.
    /// Populated during first run from emulator static field table.
    resolved_values: RwLock<HashMap<Token, ConstValue>>,
    /// Converts raw emulator values to SSA constants.
    extractor: Box<dyn FieldValueExtractor>,
    /// Capabilities this pass instance provides.
    capabilities: Vec<PassCapability>,
}

impl StaticFieldResolutionPass {
    /// Creates a new static field resolution pass.
    ///
    /// # Arguments
    ///
    /// * `pass_name` - Short identifier for logging/scheduler (e.g., `"jiejie-int32-container"`).
    /// * `pass_description` - Human-readable description for the pass scheduler.
    /// * `template_pool` - Shared emulation template pool (already warmed up with
    ///   registered warmup methods including the container .cctor).
    /// * `cctor_token` - Optional token of the container's .cctor for targeted warmup.
    ///   When `None`, a plain fork is used.
    /// * `field_tokens` - Tokens of all static fields in the container to resolve.
    /// * `extractor` - Converts raw emulator values to SSA constants.
    /// * `capabilities` - Pass capabilities this instance provides (e.g.,
    ///   `ResolvedStaticFields`).
    pub fn new(
        pass_name: &'static str,
        pass_description: &'static str,
        template_pool: Arc<EmulationTemplatePool>,
        cctor_token: Option<Token>,
        field_tokens: Vec<Token>,
        extractor: Box<dyn FieldValueExtractor>,
        capabilities: Vec<PassCapability>,
    ) -> Self {
        Self {
            pass_name,
            pass_description,
            lazy_process: ProcessCell::new("static field resolution"),
            template_pool,
            field_tokens,
            cctor_token,
            resolved_values: RwLock::new(HashMap::new()),
            extractor,
            capabilities,
        }
    }

    /// Ensures the emulation process is initialized and field values are resolved.
    ///
    /// On first call, forks the template pool (with optional targeted .cctor warmup),
    /// reads all container field values from the emulator's static field table, and
    /// converts them to SSA constants via the configured [`FieldValueExtractor`].
    /// Subsequent calls return immediately using the cached results.
    ///
    /// Thread-safe: delegates to [`ProcessCell::ensure_initialized`] which
    /// uses double-checked locking to ensure only one thread performs initialization.
    ///
    /// # Returns
    ///
    /// `true` if at least one field value was successfully resolved, `false` if
    /// initialization failed (pool fork error) or no fields could be extracted.
    fn ensure_initialized(&self) -> bool {
        // Use the lazy helper for process lifecycle; extract field values in post_init.
        let cctor_token = self.cctor_token;
        let pool = &self.template_pool;

        let result = self.lazy_process.ensure_initialized(
            || {
                if let Some(cctor) = cctor_token {
                    pool.fork_for_targeted_warmup(&[cctor])
                } else {
                    pool.fork().ok()
                }
            },
            |process| {
                // Read all field values from the emulator's static field table
                let mut values = HashMap::new();
                for field_token in &self.field_tokens {
                    match process.get_static(*field_token) {
                        Ok(Some(ref em_value)) => {
                            if let Some(const_value) =
                                self.extractor.extract(process, *field_token, em_value)
                            {
                                values.insert(*field_token, const_value);
                            }
                        }
                        Ok(None) => {
                            debug!(
                                "{}: field 0x{:08X} not found in emulator statics",
                                self.extractor.label(),
                                field_token.value()
                            );
                        }
                        Err(e) => {
                            debug!(
                                "{}: error reading field 0x{:08X}: {}",
                                self.extractor.label(),
                                field_token.value(),
                                e
                            );
                        }
                    }
                }

                if values.is_empty() && !self.field_tokens.is_empty() {
                    warn!(
                        "{}: resolved 0/{} field values - container .cctor may have failed or \
                         field types are unsupported",
                        self.extractor.label(),
                        self.field_tokens.len()
                    );
                } else {
                    info!(
                        "{}: resolved {}/{} field values via emulation",
                        self.extractor.label(),
                        values.len(),
                        self.field_tokens.len()
                    );
                }

                if let Ok(mut guard) = self.resolved_values.write() {
                    *guard = values;
                }
            },
        );

        // If the lazy helper itself failed (lock poisoned), treat as not initialized
        if result.is_err() {
            warn!(
                "{}: failed to initialize emulation process",
                self.extractor.label()
            );
            return false;
        }

        self.resolved_values.read().is_ok_and(|v| !v.is_empty())
    }
}

impl SsaPass<CilTarget, CompilerContext> for StaticFieldResolutionPass {
    fn name(&self) -> &'static str {
        self.pass_name
    }

    fn description(&self) -> &'static str {
        self.pass_description
    }

    fn modification_scope(&self) -> ModificationScope {
        ModificationScope::InstructionsOnly
    }

    fn provides(&self) -> &[PassCapability] {
        &self.capabilities
    }

    fn initialize(&mut self, _host: &CompilerContext) -> analyssa::Result<()> {
        // Eagerly initialize field values before parallel method processing.
        // This avoids a race condition where parallel run_on_method calls
        // compete on lazy initialization - losing threads would see empty
        // resolved_values and skip methods that need processing.
        self.ensure_initialized();
        Ok(())
    }

    fn run_on_method(
        &self,
        ssa: &mut SsaFunction,
        _method: &MethodRef,
        host: &CompilerContext,
    ) -> analyssa::Result<bool> {
        let assembly_arc = host.assembly().ok_or_else(|| {
            analyssa::Error::new("StaticFieldResolutionPass requires an assembly")
        })?;
        let assembly: &CilObject = &assembly_arc;
        let ctx = host;
        if !self.ensure_initialized() {
            return Ok(false);
        }

        let values = self.resolved_values.read().map_err(|e| {
            Error::LockError(format!("{} values read: {e}", self.extractor.label()))
        })?;
        if values.is_empty() {
            return Ok(false);
        }

        // Scan for LoadStaticField ops referencing container fields.
        // The field token in SSA may be a FieldDef (0x04) or MemberRef (0x0A)
        // depending on whether the IL used a cross-module reference. We try a
        // direct lookup first, then fall back to resolving MemberRef -> FieldDef
        // via the assembly's TokenResolver.
        let mut replacements: Vec<(usize, usize, SsaVarId, ConstValue)> = Vec::new();

        for (block_idx, block) in ssa.blocks().iter().enumerate() {
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                if let SsaOp::LoadStaticField { dest, field } = instr.op() {
                    let field_token = field.token();
                    let value = values.get(&field_token).or_else(|| {
                        // MemberRef fallback: resolve to FieldDef and retry lookup
                        let resolved = assembly.resolver().resolve_field(field_token)?;
                        values.get(&resolved)
                    });
                    if let Some(value) = value {
                        replacements.push((block_idx, instr_idx, *dest, value.clone()));
                    }
                }
            }
        }

        if replacements.is_empty() {
            return Ok(false);
        }

        let event_kind = self.extractor.event_kind();

        for (block_idx, instr_idx, dest, value) in &replacements {
            ssa.replace_instruction_op(
                *block_idx,
                *instr_idx,
                SsaOp::Const {
                    dest: *dest,
                    value: value.clone(),
                },
            );
            ctx.events.record(event_kind);
        }

        Ok(true)
    }

    fn finalize(&mut self, _host: &CompilerContext) -> analyssa::Result<()> {
        // Release the emulation process to free the Arc<CilObject> reference
        self.lazy_process.clear().map_err(Into::into)
    }
}
