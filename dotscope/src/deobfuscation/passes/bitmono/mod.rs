//! BitMono-specific SSA transformation passes.
//!
//! These passes reverse BitMono's obfuscation protections by operating on SSA
//! form. Each pass is created by its corresponding detection technique in
//! [`crate::deobfuscation::techniques::bitmono`] via
//! [`Technique::create_pass`](crate::deobfuscation::techniques::Technique::create_pass).
//!
//! # Passes
//!
//! | Pass | Phase | Description |
//! |------|-------|-------------|
//! | [`StringDecryptionPass`] | Simplify | Decrypts AES-256-CBC encrypted strings (requires `legacy-crypto` feature) |
//! | [`LocalEncodingReversalPass`] | Structure | Carries BitMono's encoded locals plain |
//! | [`UnmanagedStringReversalPass`] | Simplify | Replaces fake native string method calls with `ldstr` constants |

mod locals;
#[cfg(feature = "legacy-crypto")]
mod strings;
pub mod unmanaged;

#[cfg(feature = "legacy-crypto")]
pub use self::strings::StringDecryptionPass;
pub use self::{locals::LocalEncodingReversalPass, unmanaged::UnmanagedStringReversalPass};
