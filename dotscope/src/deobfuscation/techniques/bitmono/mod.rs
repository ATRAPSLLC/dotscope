//! BitMono-specific deobfuscation techniques.
//!
//! BitMono is an open-source .NET packer with 16 independent protections across
//! 4 categories. Unlike ConfuserEx (layered/interdependent), BitMono protections
//! are independent plugins, each detectable and reversible individually.
//!
//! # Technique Overview
//!
//! | Technique | Kind | Category | Description |
//! |-----------|------|----------|-------------|
//! | [`BitMonoCalli`] | SSA | Structure | Reverses CallToCalli indirect call pattern |
//! | [`BitMonoStrings`] | SSA | Value | Decrypts AES+PBKDF2 encrypted strings |
//! | [`BitMonoTokens`] | Byte | Structure | Rewrites the stale method tokens DotNetHook and CallToCalli embed |
//! | [`BitMonoHooks`] | Byte | Protection | Reverses DotNetHook method redirections |
//! | [`BitMonoUnmanaged`] | SSA | Value | Detects fake native string methods |
//! | [`BitMonoAntiDebug`] | SSA | Neutralization | Removes timing-based anti-debug checks |
//! | [`BitMonoLocals`] | SSA | Value | Restores locals LocalVariableEncoding stores encoded |
//! | [`BitMonoJunk`] | Byte | Metadata | Detects `br.s` junk prefix trampolines |
//! | [`BitMonoNops`] | SSA | Neutralization | Removes BillionNops dead methods |
//! | [`BitMonoPeRepair`] | Byte | Protection | Detects PE-level header corruptions |
//! | [`BitMonoRenamer`] | SSA | Metadata | Detects FullRenamer space-containing names |

mod calli;
mod debug;
mod hooks;
mod junk;
mod locals;
mod nops;
mod pe;
mod renamer;
mod strings;
mod tokens;
mod unmanaged;

pub use calli::BitMonoCalli;
pub use debug::BitMonoAntiDebug;
pub use hooks::BitMonoHooks;
pub use junk::BitMonoJunk;
pub use locals::BitMonoLocals;
pub use nops::BitMonoNops;
pub use pe::BitMonoPeRepair;
pub use renamer::BitMonoRenamer;
pub use strings::BitMonoStrings;
#[cfg(feature = "legacy-crypto")]
pub use strings::StringFindings;
pub use tokens::BitMonoTokens;
pub use unmanaged::BitMonoUnmanaged;
