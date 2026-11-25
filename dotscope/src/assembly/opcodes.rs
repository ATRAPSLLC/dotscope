//! CIL opcode byte constants (ECMA-335).
//!
//! This module provides the raw byte values for all CIL opcodes. Single-byte
//! opcodes are named after their mnemonic (e.g. [`CALL`] = `0x28`). Two-byte
//! opcodes that use the `0xFE` prefix have their second byte stored with an
//! `FE_` prefix (e.g. [`FE_CEQ`] = `0x01` for the `ceq` instruction `0xFE 0x01`).
//!
//! The [`FE_PREFIX`] constant holds the shared first byte `0xFE`.
#![allow(missing_docs)]

// Misc
pub const NOP: u8 = 0x00;
pub const BREAK: u8 = 0x01;

// Load/store argument shorthand
pub const LDARG_0: u8 = 0x02;
pub const LDARG_1: u8 = 0x03;
pub const LDARG_2: u8 = 0x04;
pub const LDARG_3: u8 = 0x05;

// Load/store local shorthand
pub const LDLOC_0: u8 = 0x06;
pub const LDLOC_1: u8 = 0x07;
pub const LDLOC_2: u8 = 0x08;
pub const LDLOC_3: u8 = 0x09;
pub const STLOC_0: u8 = 0x0A;
pub const STLOC_1: u8 = 0x0B;
pub const STLOC_2: u8 = 0x0C;
pub const STLOC_3: u8 = 0x0D;

// Load/store argument/local (short form)
pub const LDARG_S: u8 = 0x0E;
pub const LDARGA_S: u8 = 0x0F;
pub const STARG_S: u8 = 0x10;
pub const LDLOC_S: u8 = 0x11;
pub const LDLOCA_S: u8 = 0x12;
pub const STLOC_S: u8 = 0x13;

// Null / constant loaders
pub const LDNULL: u8 = 0x14;
pub const LDC_I4_M1: u8 = 0x15;
pub const LDC_I4_0: u8 = 0x16;
pub const LDC_I4_1: u8 = 0x17;
pub const LDC_I4_2: u8 = 0x18;
pub const LDC_I4_3: u8 = 0x19;
pub const LDC_I4_4: u8 = 0x1A;
pub const LDC_I4_5: u8 = 0x1B;
pub const LDC_I4_6: u8 = 0x1C;
pub const LDC_I4_7: u8 = 0x1D;
pub const LDC_I4_8: u8 = 0x1E;
pub const LDC_I4_S: u8 = 0x1F;
pub const LDC_I4: u8 = 0x20;
pub const LDC_I8: u8 = 0x21;
pub const LDC_R4: u8 = 0x22;
pub const LDC_R8: u8 = 0x23;

// Stack manipulation
pub const DUP: u8 = 0x25;
pub const POP: u8 = 0x26;

// Call / return
pub const JMP: u8 = 0x27;
pub const CALL: u8 = 0x28;
pub const CALLI: u8 = 0x29;
pub const RET: u8 = 0x2A;

// Branch (short form)
pub const BR_S: u8 = 0x2B;
pub const BRFALSE_S: u8 = 0x2C;
pub const BRTRUE_S: u8 = 0x2D;
pub const BEQ_S: u8 = 0x2E;
pub const BGE_S: u8 = 0x2F;
pub const BGT_S: u8 = 0x30;
pub const BLE_S: u8 = 0x31;
pub const BLT_S: u8 = 0x32;
pub const BNE_UN_S: u8 = 0x33;
pub const BGE_UN_S: u8 = 0x34;
pub const BGT_UN_S: u8 = 0x35;
pub const BLE_UN_S: u8 = 0x36;
pub const BLT_UN_S: u8 = 0x37;

// Branch (long form)
pub const BR: u8 = 0x38;
pub const BRFALSE: u8 = 0x39;
pub const BRTRUE: u8 = 0x3A;
pub const BEQ: u8 = 0x3B;
pub const BGE: u8 = 0x3C;
pub const BGT: u8 = 0x3D;
pub const BLE: u8 = 0x3E;
pub const BLT: u8 = 0x3F;
pub const BNE_UN: u8 = 0x40;
pub const BGE_UN: u8 = 0x41;
pub const BGT_UN: u8 = 0x42;
pub const BLE_UN: u8 = 0x43;
pub const BLT_UN: u8 = 0x44;

// Switch
pub const SWITCH: u8 = 0x45;

// Indirect load (ldind.*)
pub const LDIND_I1: u8 = 0x46;
pub const LDIND_U1: u8 = 0x47;
pub const LDIND_I2: u8 = 0x48;
pub const LDIND_U2: u8 = 0x49;
pub const LDIND_I4: u8 = 0x4A;
pub const LDIND_U4: u8 = 0x4B;
pub const LDIND_I8: u8 = 0x4C;
pub const LDIND_I: u8 = 0x4D;
pub const LDIND_R4: u8 = 0x4E;
pub const LDIND_R8: u8 = 0x4F;
pub const LDIND_REF: u8 = 0x50;

// Indirect store (stind.*)
pub const STIND_REF: u8 = 0x51;
pub const STIND_I1: u8 = 0x52;
pub const STIND_I2: u8 = 0x53;
pub const STIND_I4: u8 = 0x54;
pub const STIND_I8: u8 = 0x55;
pub const STIND_R4: u8 = 0x56;
pub const STIND_R8: u8 = 0x57;

// Arithmetic
pub const ADD: u8 = 0x58;
pub const SUB: u8 = 0x59;
pub const MUL: u8 = 0x5A;
pub const DIV: u8 = 0x5B;
pub const DIV_UN: u8 = 0x5C;
pub const REM: u8 = 0x5D;
pub const REM_UN: u8 = 0x5E;

// Bitwise / logical
pub const AND: u8 = 0x5F;
pub const OR: u8 = 0x60;
pub const XOR: u8 = 0x61;
pub const SHL: u8 = 0x62;
pub const SHR: u8 = 0x63;
pub const SHR_UN: u8 = 0x64;
pub const NEG: u8 = 0x65;
pub const NOT: u8 = 0x66;

// Conversion
pub const CONV_I1: u8 = 0x67;
pub const CONV_I2: u8 = 0x68;
pub const CONV_I4: u8 = 0x69;
pub const CONV_I8: u8 = 0x6A;
pub const CONV_R4: u8 = 0x6B;
pub const CONV_R8: u8 = 0x6C;
pub const CONV_U4: u8 = 0x6D;
pub const CONV_U8: u8 = 0x6E;

// Virtual call / object model
pub const CALLVIRT: u8 = 0x6F;
pub const CPOBJ: u8 = 0x70;
pub const LDOBJ: u8 = 0x71;
pub const LDSTR: u8 = 0x72;
pub const NEWOBJ: u8 = 0x73;
pub const CASTCLASS: u8 = 0x74;
pub const ISINST: u8 = 0x75;
pub const CONV_R_UN: u8 = 0x76;

// Boxing / unboxing
pub const UNBOX: u8 = 0x79;

// Exception
pub const THROW: u8 = 0x7A;

// Field access
pub const LDFLD: u8 = 0x7B;
pub const LDFLDA: u8 = 0x7C;
pub const STFLD: u8 = 0x7D;
pub const LDSFLD: u8 = 0x7E;
pub const LDSFLDA: u8 = 0x7F;
pub const STSFLD: u8 = 0x80;

// Object store
pub const STOBJ: u8 = 0x81;

// Overflow conversion (unsigned source)
pub const CONV_OVF_I1_UN: u8 = 0x82;
pub const CONV_OVF_I2_UN: u8 = 0x83;
pub const CONV_OVF_I4_UN: u8 = 0x84;
pub const CONV_OVF_I8_UN: u8 = 0x85;
pub const CONV_OVF_U1_UN: u8 = 0x86;
pub const CONV_OVF_U2_UN: u8 = 0x87;
pub const CONV_OVF_U4_UN: u8 = 0x88;
pub const CONV_OVF_U8_UN: u8 = 0x89;
pub const CONV_OVF_I_UN: u8 = 0x8A;
pub const CONV_OVF_U_UN: u8 = 0x8B;

// Boxing / arrays
pub const BOX: u8 = 0x8C;
pub const NEWARR: u8 = 0x8D;
pub const LDLEN: u8 = 0x8E;
pub const LDELEMA: u8 = 0x8F;

// Array element load
pub const LDELEM_I1: u8 = 0x90;
pub const LDELEM_U1: u8 = 0x91;
pub const LDELEM_I2: u8 = 0x92;
pub const LDELEM_U2: u8 = 0x93;
pub const LDELEM_I4: u8 = 0x94;
pub const LDELEM_U4: u8 = 0x95;
pub const LDELEM_I8: u8 = 0x96;
pub const LDELEM_I: u8 = 0x97;
pub const LDELEM_R4: u8 = 0x98;
pub const LDELEM_R8: u8 = 0x99;
pub const LDELEM_REF: u8 = 0x9A;

// Array element store
pub const STELEM_I: u8 = 0x9B;
pub const STELEM_I1: u8 = 0x9C;
pub const STELEM_I2: u8 = 0x9D;
pub const STELEM_I4: u8 = 0x9E;
pub const STELEM_I8: u8 = 0x9F;
pub const STELEM_R4: u8 = 0xA0;
pub const STELEM_R8: u8 = 0xA1;
pub const STELEM_REF: u8 = 0xA2;

// Generic array element access
pub const LDELEM: u8 = 0xA3;
pub const STELEM: u8 = 0xA4;
pub const UNBOX_ANY: u8 = 0xA5;

// Overflow conversion (signed source)
pub const CONV_OVF_I1: u8 = 0xB3;
pub const CONV_OVF_U1: u8 = 0xB4;
pub const CONV_OVF_I2: u8 = 0xB5;
pub const CONV_OVF_U2: u8 = 0xB6;
pub const CONV_OVF_I4: u8 = 0xB7;
pub const CONV_OVF_U4: u8 = 0xB8;
pub const CONV_OVF_I8: u8 = 0xB9;
pub const CONV_OVF_U8: u8 = 0xBA;

// Typed reference
pub const REFANYVAL: u8 = 0xC2;
pub const CKFINITE: u8 = 0xC3;
pub const MKREFANY: u8 = 0xC6;

// Token / conversion
pub const LDTOKEN: u8 = 0xD0;
pub const CONV_U2: u8 = 0xD1;
pub const CONV_U1: u8 = 0xD2;
pub const CONV_I: u8 = 0xD3;
pub const CONV_OVF_I: u8 = 0xD4;
pub const CONV_OVF_U: u8 = 0xD5;

// Overflow arithmetic
pub const ADD_OVF: u8 = 0xD6;
pub const ADD_OVF_UN: u8 = 0xD7;
pub const MUL_OVF: u8 = 0xD8;
pub const MUL_OVF_UN: u8 = 0xD9;
pub const SUB_OVF: u8 = 0xDA;
pub const SUB_OVF_UN: u8 = 0xDB;

// Exception handling
pub const ENDFINALLY: u8 = 0xDC;
pub const LEAVE: u8 = 0xDD;
pub const LEAVE_S: u8 = 0xDE;

// Indirect store / conversion
pub const STIND_I: u8 = 0xDF;
pub const CONV_U: u8 = 0xE0;

// Two-byte opcodes (0xFE prefix)
//
// The first byte is always FE_PREFIX; the constants below are the second byte.

pub const FE_PREFIX: u8 = 0xFE;

pub const FE_ARGLIST: u8 = 0x00;
pub const FE_CEQ: u8 = 0x01;
pub const FE_CGT: u8 = 0x02;
pub const FE_CGT_UN: u8 = 0x03;
pub const FE_CLT: u8 = 0x04;
pub const FE_CLT_UN: u8 = 0x05;
pub const FE_LDFTN: u8 = 0x06;
pub const FE_LDVIRTFTN: u8 = 0x07;
pub const FE_LDARG: u8 = 0x09;
pub const FE_LDARGA: u8 = 0x0A;
pub const FE_STARG: u8 = 0x0B;
pub const FE_LDLOC: u8 = 0x0C;
pub const FE_LDLOCA: u8 = 0x0D;
pub const FE_STLOC: u8 = 0x0E;
pub const FE_LOCALLOC: u8 = 0x0F;
pub const FE_ENDFILTER: u8 = 0x11;
pub const FE_UNALIGNED: u8 = 0x12;
pub const FE_VOLATILE: u8 = 0x13;
pub const FE_TAIL: u8 = 0x14;
pub const FE_INITOBJ: u8 = 0x15;
pub const FE_CONSTRAINED: u8 = 0x16;
pub const FE_CPBLK: u8 = 0x17;
pub const FE_INITBLK: u8 = 0x18;
pub const FE_NO: u8 = 0x19;
pub const FE_RETHROW: u8 = 0x1A;
pub const FE_SIZEOF: u8 = 0x1C;
pub const FE_REFANYTYPE: u8 = 0x1D;
pub const FE_READONLY: u8 = 0x1E;
