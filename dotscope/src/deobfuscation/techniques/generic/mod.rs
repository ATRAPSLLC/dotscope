//! Generic deobfuscation techniques.
//!
//! These techniques detect and reverse common obfuscation patterns that are not
//! specific to any single obfuscator. They serve as base-level detections that
//! obfuscator-specific techniques can supersede with more targeted logic.

mod constants;
mod debug;
mod decompiler;
pub mod delegates;
mod dump;
pub mod flattening;
mod handlers;
mod ildasm;
mod metadata;
mod opaquefields;
mod strings;

pub use constants::GenericConstants;
pub use debug::GenericAntiDebug;
pub use decompiler::GenericDecompiler;
pub use delegates::GenericDelegateProxy;
pub use dump::GenericAntiDump;
pub use flattening::GenericFlattening;
pub use handlers::GenericHandlers;
pub use ildasm::GenericIldasm;
pub use metadata::GenericMetadata;
pub use opaquefields::GenericOpaquePredicates;
pub use strings::GenericStrings;
