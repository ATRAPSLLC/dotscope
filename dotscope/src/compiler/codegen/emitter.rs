//! CIL instruction emission helpers.
//!
//! This module provides low-level functions for emitting CIL instructions with
//! proper encoding. These helpers select the most compact instruction encoding
//! based on operand values (e.g., using `ldarg.0` instead of `ldarg 0`).
//!
//! # Instruction Categories
//!
//! The emitters are organized by category:
//!
//! - **Load/Store Arguments**: `emit_ldarg`, `emit_starg`, `emit_ldarga`
//! - **Load/Store Locals**: `emit_ldloc`, `emit_stloc`, `emit_ldloca`
//! - **Constants**: `emit_ldc_i4`
//! - **Conversions**: `emit_conv`
//! - **Array Access**: `emit_ldelem`, `emit_stelem`
//! - **Indirect Access**: `emit_ldind`, `emit_stind`
//!
//! # Encoding Optimization
//!
//! Each emitter selects the most compact instruction encoding:
//!
//! ```text
//! ldarg.0, ldarg.1, ldarg.2, ldarg.3  (1 byte)
//! ldarg.s <uint8>                      (2 bytes)
//! ldarg <uint16>                       (4 bytes)
//! ```

use crate::{
    analysis::SsaType,
    assembly::{Immediate, InstructionEncoder, Operand},
    metadata::token::Token,
    Error, Result,
};

/// Emits an optimized ldc.i4 instruction for a 32-bit integer value.
///
/// Uses the most compact encoding possible:
/// - ldc.i4.m1 through ldc.i4.8 for values -1 to 8
/// - ldc.i4.s for values in -128..127
/// - ldc.i4 for all other values
///
/// # Examples
///
/// ```text
/// // Emits ldc.i4.0 (1 byte)
/// emit_ldc_i4(&mut encoder, 0)?;
///
/// // Emits ldc.i4.s 42 (2 bytes)
/// emit_ldc_i4(&mut encoder, 42)?;
///
/// // Emits ldc.i4 1000000 (5 bytes)
/// emit_ldc_i4(&mut encoder, 1_000_000)?;
/// ```
#[allow(clippy::cast_possible_truncation)] // Intentional truncation for ldc.i4.s encoding
pub fn emit_ldc_i4(encoder: &mut InstructionEncoder, v: i32) -> Result<()> {
    match v {
        -1 => encoder.emit_instruction("ldc.i4.m1", None)?,
        0 => encoder.emit_instruction("ldc.i4.0", None)?,
        1 => encoder.emit_instruction("ldc.i4.1", None)?,
        2 => encoder.emit_instruction("ldc.i4.2", None)?,
        3 => encoder.emit_instruction("ldc.i4.3", None)?,
        4 => encoder.emit_instruction("ldc.i4.4", None)?,
        5 => encoder.emit_instruction("ldc.i4.5", None)?,
        6 => encoder.emit_instruction("ldc.i4.6", None)?,
        7 => encoder.emit_instruction("ldc.i4.7", None)?,
        8 => encoder.emit_instruction("ldc.i4.8", None)?,
        x if (-128..=127).contains(&x) => {
            encoder.emit_instruction(
                "ldc.i4.s",
                Some(Operand::Immediate(Immediate::Int8(x as i8))),
            )?;
        }
        x => {
            encoder.emit_instruction("ldc.i4", Some(Operand::Immediate(Immediate::Int32(x))))?;
        }
    }
    Ok(())
}

/// Emits a ldarg instruction with optimal encoding.
///
/// - ldarg.0 through ldarg.3 for indices 0-3 (1 byte)
/// - ldarg.s for indices 4-255 (2 bytes)
/// - ldarg for indices 256+ (4 bytes)
pub fn emit_ldarg(encoder: &mut InstructionEncoder, index: u16) -> Result<()> {
    match index {
        0 => encoder.emit_instruction("ldarg.0", None)?,
        1 => encoder.emit_instruction("ldarg.1", None)?,
        2 => encoder.emit_instruction("ldarg.2", None)?,
        3 => encoder.emit_instruction("ldarg.3", None)?,
        x if x <= 255 => {
            #[allow(clippy::cast_possible_truncation)]
            let short_idx = x as u8;
            encoder.emit_instruction(
                "ldarg.s",
                Some(Operand::Immediate(Immediate::UInt8(short_idx))),
            )?;
        }
        x => {
            #[allow(clippy::cast_possible_wrap)]
            let signed_idx = x as i16;
            encoder.emit_instruction(
                "ldarg",
                Some(Operand::Immediate(Immediate::Int16(signed_idx))),
            )?;
        }
    }
    Ok(())
}

/// Emits a ldloc instruction with optimal encoding.
///
/// - ldloc.0 through ldloc.3 for indices 0-3 (1 byte)
/// - ldloc.s for indices 4-255 (2 bytes)
/// - ldloc for indices 256+ (4 bytes)
pub fn emit_ldloc(encoder: &mut InstructionEncoder, index: u16) -> Result<()> {
    match index {
        0 => encoder.emit_instruction("ldloc.0", None)?,
        1 => encoder.emit_instruction("ldloc.1", None)?,
        2 => encoder.emit_instruction("ldloc.2", None)?,
        3 => encoder.emit_instruction("ldloc.3", None)?,
        x if x <= 255 => {
            #[allow(clippy::cast_possible_truncation)]
            let short_idx = x as u8;
            encoder.emit_instruction(
                "ldloc.s",
                Some(Operand::Immediate(Immediate::UInt8(short_idx))),
            )?;
        }
        x => {
            #[allow(clippy::cast_possible_wrap)]
            let signed_idx = x as i16;
            encoder.emit_instruction(
                "ldloc",
                Some(Operand::Immediate(Immediate::Int16(signed_idx))),
            )?;
        }
    }
    Ok(())
}

/// Emits a starg instruction with optimal encoding.
///
/// - starg.s for indices 0-255 (2 bytes)
/// - starg for indices 256+ (4 bytes)
pub fn emit_starg(encoder: &mut InstructionEncoder, index: u16) -> Result<()> {
    if index <= 255 {
        #[allow(clippy::cast_possible_truncation)]
        let short_idx = index as u8;
        encoder.emit_instruction(
            "starg.s",
            Some(Operand::Immediate(Immediate::UInt8(short_idx))),
        )?;
    } else {
        #[allow(clippy::cast_possible_wrap)]
        let signed_idx = index as i16;
        encoder.emit_instruction(
            "starg",
            Some(Operand::Immediate(Immediate::Int16(signed_idx))),
        )?;
    }
    Ok(())
}

/// Emits a stloc instruction with optimal encoding.
///
/// - stloc.0 through stloc.3 for indices 0-3 (1 byte)
/// - stloc.s for indices 4-255 (2 bytes)
/// - stloc for indices 256+ (4 bytes)
pub fn emit_stloc(encoder: &mut InstructionEncoder, index: u16) -> Result<()> {
    match index {
        0 => encoder.emit_instruction("stloc.0", None)?,
        1 => encoder.emit_instruction("stloc.1", None)?,
        2 => encoder.emit_instruction("stloc.2", None)?,
        3 => encoder.emit_instruction("stloc.3", None)?,
        x if x <= 255 => {
            #[allow(clippy::cast_possible_truncation)]
            let short_idx = x as u8;
            encoder.emit_instruction(
                "stloc.s",
                Some(Operand::Immediate(Immediate::UInt8(short_idx))),
            )?;
        }
        x => {
            #[allow(clippy::cast_possible_wrap)]
            let signed_idx = x as i16;
            encoder.emit_instruction(
                "stloc",
                Some(Operand::Immediate(Immediate::Int16(signed_idx))),
            )?;
        }
    }
    Ok(())
}

/// Emits a ldarga instruction with optimal encoding.
///
/// - ldarga.s for indices 0-255 (2 bytes)
/// - ldarga for indices 256+ (4 bytes)
pub fn emit_ldarga(encoder: &mut InstructionEncoder, index: u16) -> Result<()> {
    if index <= 255 {
        #[allow(clippy::cast_possible_truncation)]
        let short_idx = index as u8;
        encoder.emit_instruction(
            "ldarga.s",
            Some(Operand::Immediate(Immediate::UInt8(short_idx))),
        )?;
    } else {
        #[allow(clippy::cast_possible_wrap)]
        let signed_idx = index as i16;
        encoder.emit_instruction(
            "ldarga",
            Some(Operand::Immediate(Immediate::Int16(signed_idx))),
        )?;
    }
    Ok(())
}

/// Emits a ldloca instruction with optimal encoding.
///
/// - ldloca.s for indices 0-255 (2 bytes)
/// - ldloca for indices 256+ (4 bytes)
pub fn emit_ldloca(encoder: &mut InstructionEncoder, index: u16) -> Result<()> {
    if index <= 255 {
        #[allow(clippy::cast_possible_truncation)]
        let short_idx = index as u8;
        encoder.emit_instruction(
            "ldloca.s",
            Some(Operand::Immediate(Immediate::UInt8(short_idx))),
        )?;
    } else {
        #[allow(clippy::cast_possible_wrap)]
        let signed_idx = index as i16;
        encoder.emit_instruction(
            "ldloca",
            Some(Operand::Immediate(Immediate::Int16(signed_idx))),
        )?;
    }
    Ok(())
}

/// Emits a conversion of the value on the stack, of type `source` when known, to `target`.
///
/// The IR's integer conversion reads its operand at the operand's own declared width and,
/// widening, extends it as `unsigned` says; CIL's `conv` converts the `int32` or `int64` on
/// the evaluation stack (ECMA-335 III.1.1, III.3.27 - III.3.30), where a value of 16 bits or
/// fewer is held extended by its own type's signedness. So:
///
/// - A narrow source read the other way than its own signedness is first re-extended as the
///   conversion reads it (`conv.u1` for an `sbyte` read unsigned), wherever the difference
///   shows: in a widening, an overflow check or a conversion to a float. A truncation keeps
///   the low bits either way. The lift states such readings itself; a pass may write one.
/// - An unchecked widening to 64 bits or to a native integer extends as `unsigned` says:
///   `conv.u8` zero-extends and `conv.i8` sign-extends, whatever the target's signedness
///   (C# spells `(ulong)intValue` `conv.i8`). A narrower target names its own width and
///   signedness, which is what the result is.
/// - An unsigned integer converted to a float goes through `conv.r.un`, which reads it as
///   unsigned, and then to the target width: `conv.r4` or `conv.r8` alone read it as signed,
///   and `uint` 3000000000 came out negative.
///
/// A target with no conversion CIL can spell is an error, not a conversion left out.
///
/// # Arguments
///
/// * `source` - The type of the value converted, when known.
/// * `target` - The type to convert to.
/// * `overflow_check` - Whether to check for overflow.
/// * `unsigned` - Whether the source value is read as unsigned.
///
/// # Errors
///
/// Returns [`Error::CodegenFailed`] for a target no `conv` produces.
pub fn emit_conv(
    encoder: &mut InstructionEncoder,
    source: Option<&SsaType>,
    target: &SsaType,
    overflow_check: bool,
    unsigned: bool,
) -> Result<()> {
    let float = matches!(target, SsaType::F32 | SsaType::F64);
    let target_bits = target.size_bytes().map(|bytes| bytes.saturating_mul(8));
    if let Some((bits, own_unsigned)) = source.and_then(|source| match source {
        SsaType::I8 => Some((8, false)),
        SsaType::U8 => Some((8, true)),
        SsaType::I16 => Some((16, false)),
        SsaType::U16 | SsaType::Char => Some((16, true)),
        _ => None,
    }) {
        let widens = target_bits.is_none_or(|target| target > bits);
        if own_unsigned != unsigned && (overflow_check || float || widens) {
            let extension = match (bits, unsigned) {
                (8, true) => "conv.u1",
                (8, false) => "conv.i1",
                (_, true) => "conv.u2",
                (_, false) => "conv.i2",
            };
            encoder.emit_instruction(extension, None)?;
        }
    }
    if float {
        if unsigned {
            encoder.emit_instruction("conv.r.un", None)?;
        }
        let width = if matches!(target, SsaType::F32) {
            "conv.r4"
        } else {
            "conv.r8"
        };
        encoder.emit_instruction(width, None)?;
        return Ok(());
    }
    let base = match (target, overflow_check) {
        // An unchecked widening extends as the source is read.
        (SsaType::I64 | SsaType::U64, false) => {
            if unsigned {
                "u8"
            } else {
                "i8"
            }
        }
        (SsaType::NativeInt | SsaType::NativeUInt, false) => {
            if unsigned {
                "u"
            } else {
                "i"
            }
        }
        (SsaType::I8, _) => "i1",
        (SsaType::I16, _) => "i2",
        (SsaType::I32, _) => "i4",
        (SsaType::I64, _) => "i8",
        (SsaType::U8, _) => "u1",
        (SsaType::U16 | SsaType::Char, _) => "u2",
        (SsaType::U32, _) => "u4",
        (SsaType::U64, _) => "u8",
        (SsaType::NativeInt, _) => "i",
        (SsaType::NativeUInt, _) => "u",
        (other, _) => {
            return Err(Error::CodegenFailed(format!(
                "no CIL conversion produces {other:?}"
            )))
        }
    };
    let mnemonic = match (overflow_check, unsigned) {
        (false, _) => format!("conv.{base}"),
        (true, false) => format!("conv.ovf.{base}"),
        (true, true) => format!("conv.ovf.{base}.un"),
    };
    encoder.emit_instruction(&mnemonic, None)?;
    Ok(())
}

/// How a typed load or store through an array element or a pointer is
/// spelled: a fixed-width opcode suffix, or the token form for a value type.
enum Access {
    /// `ldelem.{suffix}` and its relatives.
    Suffix(&'static str),
    /// `ldelem <token>`, `ldobj <token>` and their stores.
    Token(Token),
}

/// Whether a load or store of `ty` names it by a TypeSpec token: a type with
/// no fixed-width opcode whose type carries no token of its own.
#[must_use]
pub fn needs_type_spec(ty: &SsaType) -> bool {
    match ty {
        SsaType::GenericParam(_) | SsaType::MethodGenericParam(_) | SsaType::TypedReference => true,
        SsaType::GenericInst(base, _) => !base.is_reference(),
        _ => false,
    }
}

/// The access a load of `ty` uses. Loads distinguish signedness.
///
/// `spec` is the TypeSpec token naming `ty`, for a type [`needs_type_spec`].
fn load_access(ty: &SsaType, spec: Option<Token>) -> Result<Access> {
    Ok(match ty {
        SsaType::I8 => Access::Suffix("i1"),
        SsaType::U8 | SsaType::Bool => Access::Suffix("u1"),
        SsaType::I16 => Access::Suffix("i2"),
        SsaType::U16 | SsaType::Char => Access::Suffix("u2"),
        SsaType::I32 => Access::Suffix("i4"),
        SsaType::U32 => Access::Suffix("u4"),
        SsaType::I64 | SsaType::U64 => Access::Suffix("i8"),
        SsaType::F32 => Access::Suffix("r4"),
        SsaType::F64 => Access::Suffix("r8"),
        _ => store_access(ty, spec)?,
    })
}

/// The access a store of `ty` uses. Stores name only the width.
///
/// `spec` is as for [`load_access`].
fn store_access(ty: &SsaType, spec: Option<Token>) -> Result<Access> {
    Ok(match ty {
        SsaType::I8 | SsaType::U8 | SsaType::Bool => Access::Suffix("i1"),
        SsaType::I16 | SsaType::U16 | SsaType::Char => Access::Suffix("i2"),
        SsaType::I32 | SsaType::U32 => Access::Suffix("i4"),
        SsaType::I64 | SsaType::U64 => Access::Suffix("i8"),
        SsaType::F32 => Access::Suffix("r4"),
        SsaType::F64 => Access::Suffix("r8"),
        SsaType::NativeInt | SsaType::NativeUInt | SsaType::Pointer(_) | SsaType::FnPtr(_) => {
            Access::Suffix("i")
        }
        SsaType::Object
        | SsaType::String
        | SsaType::Class(_)
        | SsaType::Array(_, _)
        | SsaType::Null => Access::Suffix("ref"),
        SsaType::GenericInst(base, _) if base.is_reference() => Access::Suffix("ref"),
        SsaType::ValueType(type_ref) => Access::Token(type_ref.token()),
        other if needs_type_spec(other) => match spec {
            Some(token) => Access::Token(token),
            None => {
                return Err(Error::CodegenFailed(format!(
                    "a load or store of {other:?} needs a TypeSpec token, and none was interned"
                )))
            }
        },
        other => {
            return Err(Error::CodegenFailed(format!(
                "no load or store opcode for an element or pointee of type {other:?}"
            )))
        }
    })
}

/// Emits a ldelem instruction based on element type.
///
/// # Errors
///
/// Returns [`Error::CodegenFailed`] for an element type with no opcode, or one
/// that [`needs_type_spec`] when `spec` is `None`.
pub fn emit_ldelem(
    encoder: &mut InstructionEncoder,
    elem_type: &SsaType,
    spec: Option<Token>,
) -> Result<()> {
    match load_access(elem_type, spec)? {
        Access::Suffix(suffix) => encoder.emit_instruction(&format!("ldelem.{suffix}"), None),
        Access::Token(token) => encoder.emit_instruction("ldelem", Some(Operand::Token(token))),
    }
}

/// Emits a stelem instruction based on element type.
///
/// # Errors
///
/// As for [`emit_ldelem`].
pub fn emit_stelem(
    encoder: &mut InstructionEncoder,
    elem_type: &SsaType,
    spec: Option<Token>,
) -> Result<()> {
    match store_access(elem_type, spec)? {
        Access::Suffix(suffix) => encoder.emit_instruction(&format!("stelem.{suffix}"), None),
        Access::Token(token) => encoder.emit_instruction("stelem", Some(Operand::Token(token))),
    }
}

/// Emits a ldind instruction based on value type, or `ldobj` for a value type.
///
/// # Errors
///
/// As for [`emit_ldelem`].
pub fn emit_ldind(
    encoder: &mut InstructionEncoder,
    value_type: &SsaType,
    spec: Option<Token>,
) -> Result<()> {
    match load_access(value_type, spec)? {
        Access::Suffix(suffix) => encoder.emit_instruction(&format!("ldind.{suffix}"), None),
        Access::Token(token) => encoder.emit_instruction("ldobj", Some(Operand::Token(token))),
    }
}

/// Emits a stind instruction based on value type, or `stobj` for a value type.
///
/// # Errors
///
/// As for [`emit_ldelem`].
pub fn emit_stind(
    encoder: &mut InstructionEncoder,
    value_type: &SsaType,
    spec: Option<Token>,
) -> Result<()> {
    match store_access(value_type, spec)? {
        Access::Suffix(suffix) => encoder.emit_instruction(&format!("stind.{suffix}"), None),
        Access::Token(token) => encoder.emit_instruction("stobj", Some(Operand::Token(token))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::TypeRef;

    #[test]
    fn test_emit_ldc_i4_special_values() {
        let mut encoder = InstructionEncoder::new();

        // Test special values -1 to 8
        emit_ldc_i4(&mut encoder, -1).unwrap();
        emit_ldc_i4(&mut encoder, 0).unwrap();
        emit_ldc_i4(&mut encoder, 1).unwrap();
        emit_ldc_i4(&mut encoder, 8).unwrap();

        // Test short form
        emit_ldc_i4(&mut encoder, 42).unwrap();
        emit_ldc_i4(&mut encoder, -100).unwrap();

        // Test full form
        emit_ldc_i4(&mut encoder, 1000).unwrap();
        emit_ldc_i4(&mut encoder, -1000).unwrap();

        let (bytecode, _, _) = encoder.finalize().unwrap();
        assert!(!bytecode.is_empty());
    }

    #[test]
    fn test_emit_ldarg_encoding() {
        let mut encoder = InstructionEncoder::new();

        // Short forms
        emit_ldarg(&mut encoder, 0).unwrap();
        emit_ldarg(&mut encoder, 1).unwrap();
        emit_ldarg(&mut encoder, 2).unwrap();
        emit_ldarg(&mut encoder, 3).unwrap();

        // ldarg.s form
        emit_ldarg(&mut encoder, 10).unwrap();

        // Full form
        emit_ldarg(&mut encoder, 300).unwrap();

        let (bytecode, _, _) = encoder.finalize().unwrap();
        assert!(!bytecode.is_empty());
    }

    #[test]
    fn test_emit_ldloc_encoding() {
        let mut encoder = InstructionEncoder::new();

        // Short forms
        emit_ldloc(&mut encoder, 0).unwrap();
        emit_ldloc(&mut encoder, 3).unwrap();

        // ldloc.s form
        emit_ldloc(&mut encoder, 100).unwrap();

        let (bytecode, _, _) = encoder.finalize().unwrap();
        assert!(!bytecode.is_empty());
    }

    #[test]
    fn test_emit_stloc_encoding() {
        let mut encoder = InstructionEncoder::new();

        // Push values before storing (stloc pops 1 value)
        emit_ldc_i4(&mut encoder, 1).unwrap();
        emit_stloc(&mut encoder, 0).unwrap();

        emit_ldc_i4(&mut encoder, 2).unwrap();
        emit_stloc(&mut encoder, 3).unwrap();

        // stloc.s form
        emit_ldc_i4(&mut encoder, 3).unwrap();
        emit_stloc(&mut encoder, 100).unwrap();

        let (bytecode, _, _) = encoder.finalize().unwrap();
        assert!(!bytecode.is_empty());
    }

    /// The mnemonics `emit` produces, decoded from the bytes.
    fn mnemonics(
        emit: impl FnOnce(&mut InstructionEncoder) -> Result<()>,
    ) -> Result<Vec<&'static str>> {
        let mut encoder = InstructionEncoder::new();
        // Operands the instruction consumes, as far as the depth check cares.
        encoder.set_stack_depth(8);
        emit(&mut encoder)?;
        encoder.emit_instruction("ret", None)?;
        let (bytecode, _, _) = encoder.finalize()?;
        let mut names: Vec<&'static str> =
            crate::assembly::decode_stream(&mut crate::Parser::new(&bytecode), 0)?
                .iter()
                .map(|instr| instr.mnemonic)
                .collect();
        names.pop();
        Ok(names)
    }

    #[test]
    fn conversions_are_selected_exactly() {
        let cases: &[(SsaType, bool, bool, &[&str])] = &[
            (SsaType::I8, false, false, &["conv.i1"]),
            (SsaType::U16, false, false, &["conv.u2"]),
            (SsaType::Char, false, false, &["conv.u2"]),
            (SsaType::I64, true, false, &["conv.ovf.i8"]),
            (SsaType::U32, true, true, &["conv.ovf.u4.un"]),
            (SsaType::NativeUInt, true, true, &["conv.ovf.u.un"]),
            (SsaType::F64, false, false, &["conv.r8"]),
            (SsaType::F32, false, true, &["conv.r.un", "conv.r4"]),
            (SsaType::F64, false, true, &["conv.r.un", "conv.r8"]),
        ];
        for (target, overflow, unsigned, expected) in cases {
            let got = mnemonics(|e| emit_conv(e, None, target, *overflow, *unsigned)).unwrap();
            assert_eq!(
                &got, expected,
                "{target:?} overflow={overflow} unsigned={unsigned}"
            );
        }
        assert!(mnemonics(|e| emit_conv(e, None, &SsaType::Bool, false, false)).is_err());
        assert!(mnemonics(|e| emit_conv(e, None, &SsaType::Object, false, false)).is_err());
    }

    /// An unchecked widening extends as the conversion reads its source, not as the
    /// target's type is signed: `IntConv { target: U64, unsigned: false }` of an `int32`
    /// sign-extends, and `IntConv { target: I64, unsigned: true }` zero-extends.
    #[test]
    fn a_widening_extends_as_its_source_is_read() {
        let cases: &[(SsaType, bool, &[&str])] = &[
            (SsaType::U64, false, &["conv.i8"]),
            (SsaType::I64, true, &["conv.u8"]),
            (SsaType::NativeUInt, false, &["conv.i"]),
            (SsaType::NativeInt, true, &["conv.u"]),
        ];
        for (target, unsigned, expected) in cases {
            let got =
                mnemonics(|e| emit_conv(e, Some(&SsaType::I32), target, false, *unsigned)).unwrap();
            assert_eq!(&got, expected, "{target:?} unsigned={unsigned}");
        }
    }

    /// A narrow source on the stack is extended by its own signedness; read the other way,
    /// it is re-extended first wherever that shows, and not for a truncation.
    #[test]
    fn a_narrow_source_read_the_other_way_is_re_extended() {
        let cases: &[(SsaType, SsaType, bool, bool, &[&str])] = &[
            (
                SsaType::I8,
                SsaType::I64,
                false,
                true,
                &["conv.u1", "conv.u8"],
            ),
            (
                SsaType::U16,
                SsaType::U64,
                false,
                false,
                &["conv.i2", "conv.i8"],
            ),
            (
                SsaType::Char,
                SsaType::I32,
                false,
                false,
                &["conv.i2", "conv.i4"],
            ),
            (
                SsaType::I8,
                SsaType::U8,
                true,
                true,
                &["conv.u1", "conv.ovf.u1.un"],
            ),
            (
                SsaType::I16,
                SsaType::F64,
                false,
                true,
                &["conv.u2", "conv.r.un", "conv.r8"],
            ),
            (SsaType::I8, SsaType::I64, false, false, &["conv.i8"]),
            (SsaType::U8, SsaType::I64, false, true, &["conv.u8"]),
            (SsaType::I16, SsaType::U8, false, true, &["conv.u1"]),
        ];
        for (source, target, overflow, unsigned, expected) in cases {
            let got =
                mnemonics(|e| emit_conv(e, Some(source), target, *overflow, *unsigned)).unwrap();
            assert_eq!(
                &got, expected,
                "{source:?} -> {target:?} overflow={overflow} unsigned={unsigned}"
            );
        }
    }

    #[test]
    fn element_and_indirect_access_is_selected_exactly() {
        let value_type = SsaType::ValueType(TypeRef::new(Token::new(0x0200_0005)));
        let cases: &[(SsaType, &str, &str, &str, &str)] = &[
            (
                SsaType::I8,
                "ldelem.i1",
                "stelem.i1",
                "ldind.i1",
                "stind.i1",
            ),
            (
                SsaType::Bool,
                "ldelem.u1",
                "stelem.i1",
                "ldind.u1",
                "stind.i1",
            ),
            (
                SsaType::Char,
                "ldelem.u2",
                "stelem.i2",
                "ldind.u2",
                "stind.i2",
            ),
            (
                SsaType::U32,
                "ldelem.u4",
                "stelem.i4",
                "ldind.u4",
                "stind.i4",
            ),
            (
                SsaType::U64,
                "ldelem.i8",
                "stelem.i8",
                "ldind.i8",
                "stind.i8",
            ),
            (
                SsaType::F32,
                "ldelem.r4",
                "stelem.r4",
                "ldind.r4",
                "stind.r4",
            ),
            (
                SsaType::NativeUInt,
                "ldelem.i",
                "stelem.i",
                "ldind.i",
                "stind.i",
            ),
            (
                SsaType::String,
                "ldelem.ref",
                "stelem.ref",
                "ldind.ref",
                "stind.ref",
            ),
            (value_type, "ldelem", "stelem", "ldobj", "stobj"),
        ];
        for (ty, ldelem, stelem, ldind, stind) in cases {
            assert_eq!(
                mnemonics(|e| emit_ldelem(e, ty, None)).unwrap(),
                [*ldelem],
                "{ty:?}"
            );
            assert_eq!(
                mnemonics(|e| emit_stelem(e, ty, None)).unwrap(),
                [*stelem],
                "{ty:?}"
            );
            assert_eq!(
                mnemonics(|e| emit_ldind(e, ty, None)).unwrap(),
                [*ldind],
                "{ty:?}"
            );
            assert_eq!(
                mnemonics(|e| emit_stind(e, ty, None)).unwrap(),
                [*stind],
                "{ty:?}"
            );
        }
        // A type named by a TypeSpec uses the token form with the token it
        // is given, and fails without one; a type with no form fails anyway.
        let spec = Token::new(0x1B00_0001);
        for named in [
            SsaType::GenericParam(0),
            SsaType::MethodGenericParam(1),
            SsaType::TypedReference,
            SsaType::GenericInst(
                Box::new(SsaType::ValueType(TypeRef::new(Token::new(0x0100_0002)))),
                vec![SsaType::I32],
            ),
        ] {
            assert_eq!(
                mnemonics(|e| emit_ldelem(e, &named, Some(spec))).unwrap(),
                ["ldelem"],
                "{named:?}"
            );
            assert_eq!(
                mnemonics(|e| emit_stind(e, &named, Some(spec))).unwrap(),
                ["stobj"],
                "{named:?}"
            );
            assert!(
                mnemonics(|e| emit_ldelem(e, &named, None)).is_err(),
                "{named:?}"
            );
        }
        let reference_inst = SsaType::GenericInst(
            Box::new(SsaType::Class(TypeRef::new(Token::new(0x0100_0003)))),
            vec![SsaType::I32],
        );
        assert_eq!(
            mnemonics(|e| emit_ldelem(e, &reference_inst, None)).unwrap(),
            ["ldelem.ref"]
        );
        assert!(mnemonics(|e| emit_stind(e, &SsaType::Unknown, Some(spec))).is_err());
    }
}
