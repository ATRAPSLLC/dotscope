//! Native method to CIL conversion pass.
//!
//! This module provides infrastructure to convert native x86 methods to CIL,
//! enabling deobfuscation of assemblies that use native code for key computation
//! (such as ConfuserEx's x86Predicate protection).
//!
//! # Overview
//!
//! The conversion pipeline:
//!
//! ```text
//! x86 bytes → decode → build CFG → SSA → codegen → CIL bytes → patch method
//! ```
//!
//! # Usage
//!
//! ```no_run
//! use dotscope::deobfuscation::NativeMethodConversionPass;
//!
//! let mut converter = NativeMethodConversionPass::new();
//! converter.register_target(native_method_token);
//!
//! let stats = converter.run(&mut cil_assembly, file)?;
//! println!("Converted {} methods", stats.converted);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Limitations
//!
//! - Only supports x86/x64 code (not ARM or other architectures)
//! - Only supports simple DynCipher-style code patterns
//! - Methods with unsupported instructions will be skipped

use rustc_hash::FxHashSet;

use crate::{
    analysis::{
        x86_decode_all, x86_detect_prologue, X86Function, X86PrologueKind, X86ToSsaTranslator,
    },
    cilassembly::{CilAssembly, MethodBodyBuilder},
    compiler::SsaCodeGenerator,
    file::File,
    metadata::{
        method::MethodImplCodeType,
        tables::{MethodDefRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Statistics from native method conversion.
#[derive(Debug, Clone, Default)]
pub struct ConversionStats {
    /// Number of methods successfully converted.
    pub converted: usize,
    /// Number of methods that failed conversion.
    pub failed: usize,
    /// Tokens of methods that failed conversion.
    pub failed_tokens: Vec<Token>,
    /// Error messages for failed conversions.
    pub errors: Vec<String>,
}

/// Pass that converts native x86 methods to CIL.
///
/// This pass operates at the byte level, before SSA construction. It reads
/// x86 machine code from native method RVAs, translates it to SSA form using
/// the x86 analysis module, generates CIL bytecode, and patches the method
/// body in the assembly.
///
/// # Example
///
/// ```no_run
/// use dotscope::deobfuscation::NativeMethodConversionPass;
///
/// // Create converter and register native methods to convert
/// let mut converter = NativeMethodConversionPass::new();
/// converter.register_target(token1);
/// converter.register_target(token2);
///
/// // Run conversion
/// let stats = converter.run(&mut cil_assembly, file)?;
/// println!("Converted {}/{} methods",
///          stats.converted,
///          stats.converted + stats.failed);
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct NativeMethodConversionPass {
    /// Tokens of native methods to convert.
    targets: FxHashSet<Token>,
    /// Whether to skip the DynCipher prologue when decoding.
    skip_prologue: bool,
    /// Bitness override (None = auto-detect from PE header).
    bitness: Option<u32>,
}

impl Default for NativeMethodConversionPass {
    fn default() -> Self {
        Self::new()
    }
}

impl NativeMethodConversionPass {
    /// Creates a new native method conversion pass.
    #[must_use]
    pub fn new() -> Self {
        Self {
            targets: FxHashSet::default(),
            skip_prologue: true,
            bitness: None,
        }
    }

    /// Registers a native method for conversion.
    ///
    /// # Arguments
    ///
    /// * `token` - The metadata token of the native method to convert.
    pub fn register_target(&mut self, token: Token) {
        self.targets.insert(token);
    }

    /// Registers multiple native methods for conversion.
    ///
    /// # Arguments
    ///
    /// * `tokens` - Iterator of metadata tokens to register.
    pub fn register_targets(&mut self, tokens: impl IntoIterator<Item = Token>) {
        self.targets.extend(tokens);
    }

    /// Sets whether to skip the DynCipher prologue when decoding.
    ///
    /// Default is `true`. When enabled, the decoder will skip over the
    /// standard 20-byte DynCipher prologue that handles calling convention
    /// differences between 32-bit and 64-bit code.
    #[must_use]
    pub fn with_skip_prologue(mut self, skip: bool) -> Self {
        self.skip_prologue = skip;
        self
    }

    /// Sets the bitness for x86 decoding.
    ///
    /// If not set, the bitness is auto-detected from the PE header.
    /// Use this to override auto-detection if needed.
    ///
    /// # Arguments
    ///
    /// * `bitness` - 32 for x86, 64 for x64.
    #[must_use]
    pub fn with_bitness(mut self, bitness: u32) -> Self {
        self.bitness = Some(bitness);
        self
    }

    /// Returns the number of registered targets.
    #[must_use]
    pub fn target_count(&self) -> usize {
        self.targets.len()
    }

    /// Returns true if there are no registered targets.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }

    /// Runs the conversion pass on the assembly.
    ///
    /// For each registered native method:
    /// 1. Reads x86 bytes from the method's RVA
    /// 2. Decodes the x86 instructions
    /// 3. Builds a CFG and translates to SSA
    /// 4. Generates CIL bytecode from SSA
    /// 5. Patches the method body and updates impl flags
    ///
    /// # Arguments
    ///
    /// * `assembly` - The mutable CIL assembly to modify.
    /// * `file` - The PE file for reading native code bytes.
    ///
    /// # Returns
    ///
    /// Statistics about the conversion (successes and failures).
    ///
    /// # Errors
    ///
    /// Returns an error only for critical failures that prevent any processing.
    /// Individual method conversion failures are recorded in the stats.
    pub fn run(&self, assembly: &mut CilAssembly, file: &File) -> Result<ConversionStats> {
        let mut stats = ConversionStats::default();

        if self.targets.is_empty() {
            return Ok(stats);
        }

        // Determine bitness from PE header if not overridden
        let bitness = self
            .bitness
            .unwrap_or_else(|| if file.pe().is_64bit { 64 } else { 32 });

        // Process each target method
        for &token in &self.targets {
            match self.convert_method(assembly, file, token, bitness) {
                Ok(()) => {
                    stats.converted = stats.converted.saturating_add(1);
                }
                Err(e) => {
                    stats.failed = stats.failed.saturating_add(1);
                    stats.failed_tokens.push(token);
                    stats.errors.push(format!("0x{:08x}: {}", token.value(), e));
                }
            }
        }

        Ok(stats)
    }

    /// Converts a single native method to CIL.
    fn convert_method(
        &self,
        assembly: &mut CilAssembly,
        file: &File,
        token: Token,
        bitness: u32,
    ) -> Result<()> {
        // Step 1: Get the method's RVA and verify it's a native method
        let rid = token.row();
        // Note: closure needed here - method reference with turbofish breaks downstream type inference
        #[allow(clippy::redundant_closure_for_method_calls)]
        let method_row = assembly
            .view()
            .tables()
            .and_then(|t| t.table::<MethodDefRaw>())
            .and_then(|table| table.get(rid).ok().flatten())
            .ok_or_else(|| Error::X86Error(format!("MethodDef row {rid} not found for token")))?;

        // Verify this is actually a native method
        let impl_code_type = MethodImplCodeType::from_impl_flags(method_row.impl_flags);
        if !impl_code_type.contains(MethodImplCodeType::NATIVE) {
            return Err(Error::X86Error(format!(
                "Method 0x{:08x} is not a native method",
                token.value()
            )));
        }

        if method_row.rva == 0 {
            return Err(Error::X86Error(format!(
                "Method 0x{:08x} has no RVA",
                token.value()
            )));
        }

        // Step 2: Get x86 bytes from the RVA
        let x86_bytes = file.section_bounded(method_row.rva as usize)?;

        // Step 3: Detect prologue and adjust bytes if needed
        let (decode_bytes, base_offset) = if self.skip_prologue {
            let prologue = x86_detect_prologue(x86_bytes, bitness);
            if prologue.kind == X86PrologueKind::DynCipher {
                // Skip the prologue
                let rest = x86_bytes.get(prologue.size..).ok_or_else(|| {
                    Error::X86Error(format!(
                        "Method 0x{:08x}: prologue size {} exceeds bytes available",
                        token.value(),
                        prologue.size
                    ))
                })?;
                (rest, prologue.size as u64)
            } else {
                // No recognized prologue, decode from start
                (x86_bytes, 0u64)
            }
        } else {
            (x86_bytes, 0u64)
        };

        // Step 4: Decode x86 instructions
        let instructions = x86_decode_all(decode_bytes, bitness, base_offset)?;

        if instructions.is_empty() {
            return Err(Error::X86Error("No instructions decoded".to_string()));
        }

        // Step 5: Build CFG
        let cfg = X86Function::new(&instructions, bitness, base_offset);

        // Step 6: Translate to SSA
        let translator = X86ToSsaTranslator::new(&cfg);
        let ssa_function = translator.translate()?;

        // Step 7: Generate CIL bytecode and build method body
        let mut codegen = SsaCodeGenerator::new();
        let result = codegen.compile(&ssa_function, assembly)?;
        let (method_body, _) = MethodBodyBuilder::from_compilation(
            result.bytecode,
            result.max_stack,
            result.locals,
            result.exception_handlers,
        )
        .init_locals(false)
        .build(assembly)?;

        // Step 9: Store the method body and get placeholder RVA
        let new_rva = assembly.store_method_body(method_body);

        // Step 10: Update the MethodDef row with new RVA and change to CIL managed method.
        let updated_row = MethodDefRaw {
            rid: method_row.rid,
            token: method_row.token,
            offset: method_row.offset,
            rva: new_rva,
            // Clear native-specific bits: CodeType (0x0003), Unmanaged (0x0004), PreserveSig (0x0080)
            impl_flags: (method_row.impl_flags & !0x0087) | MethodImplCodeType::IL.bits(),
            // Clear PINVOKE_IMPL (0x2000) from method flags since this is now a CIL method
            flags: method_row.flags & !0x2000,
            name: method_row.name,
            signature: method_row.signature,
            param_list: method_row.param_list,
        };

        assembly.table_row_update(
            TableId::MethodDef,
            rid,
            TableDataOwned::MethodDef(updated_row),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conversion_pass_new() {
        let pass = NativeMethodConversionPass::new();
        assert!(pass.is_empty());
        assert_eq!(pass.target_count(), 0);
    }

    #[test]
    fn test_register_targets() {
        let mut pass = NativeMethodConversionPass::new();

        let token1 = Token::new(0x06000001);
        let token2 = Token::new(0x06000002);

        pass.register_target(token1);
        assert_eq!(pass.target_count(), 1);

        pass.register_target(token2);
        assert_eq!(pass.target_count(), 2);

        // Duplicate registration should not increase count
        pass.register_target(token1);
        assert_eq!(pass.target_count(), 2);
    }

    #[test]
    fn test_register_multiple_targets() {
        let mut pass = NativeMethodConversionPass::new();

        let tokens = vec![
            Token::new(0x06000001),
            Token::new(0x06000002),
            Token::new(0x06000003),
        ];

        pass.register_targets(tokens);
        assert_eq!(pass.target_count(), 3);
    }

    #[test]
    fn test_builder_pattern() {
        let pass = NativeMethodConversionPass::new()
            .with_skip_prologue(false)
            .with_bitness(64);

        assert!(!pass.skip_prologue);
        assert_eq!(pass.bitness, Some(64));
    }
}
