//! JIEJIE.NET-specific deobfuscation techniques.
//!
//! JIEJIE.NET is an IL-text-level obfuscator that operates through ildasm/ilasm.
//! Detection is purely structural — no reliance on type or method names, since
//! JIEJIE.NET's rename feature transforms all identifiers.
//!
//! # Techniques
//!
//! | ID | Pattern | Category |
//! |---|---|---|
//! | `jiejienet.constants` | All-static-initonly-int32 class with ldc.i8 delta chain .cctor | Value |
//! | `jiejienet.strings` | Classes with `dcsoft(byte[], int64) -> string` decryptor | Value |
//! | `jiejienet.typeof` | RuntimeTypeHandle[] container with index accessor | Value |
//! | `jiejienet.arrays` | RuntimeFieldHandle[] container with index accessor | Value |
//! | `jiejienet.resources` | Stream subclass nested in type with Dictionary<string,byte[]> | Value |

// Detection techniques
pub mod arrays;
mod constants;
pub mod resources;
mod strings;
mod typeofs;

pub use arrays::JiejieNetArrays;
pub use constants::JiejieNetConstants;
pub use resources::JiejieNetResources;
pub use strings::JiejieNetStrings;
pub use typeofs::JiejieNetTypeOf;
