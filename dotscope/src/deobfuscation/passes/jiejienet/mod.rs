//! JIEJIE.NET-specific SSA transformation passes.
//!
//! These passes reverse JIEJIE.NET's value-level obfuscations by replacing
//! obfuscated field loads and container accessor calls with their resolved
//! constant values. Each pass is created by its corresponding detection
//! technique in [`crate::deobfuscation::techniques::jiejienet`] via
//! [`Technique::create_pass`](crate::deobfuscation::techniques::Technique::create_pass).
//!
//! # Passes
//!
//! | Pass | Phase | Description |
//! |------|-------|-------------|
//! | [`TypeOfRestorationPass`] | Value | Restores `ldtoken` type references from RuntimeTypeHandleContainer accessor calls |
//! | [`ArrayInitRestorationPass`] | Value | Restores `ldtoken` field references from RuntimeFieldHandleContainer accessor calls |
//! | [`ResourceRestorationPass`] | Simplify | Redirects resource interception calls back to original BCL methods |

mod arrays;
mod resources;
mod typeofs;

pub use self::{
    arrays::ArrayInitRestorationPass,
    resources::{ResourceRestorationPass, ResourceTarget},
    typeofs::TypeOfRestorationPass,
};
