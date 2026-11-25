//! Application domain simulation for .NET emulation.
//!
//! This module provides [`AppDomainState`] which simulates the behavior of a .NET
//! Application Domain (AppDomain) during emulation. AppDomains in .NET serve as
//! isolation boundaries for applications, managing loaded assemblies and interned
//! strings.
//!
//! # Overview
//!
//! In the .NET runtime, an AppDomain provides:
//!
//! - **Assembly Management**: Loading, tracking, and resolving assemblies
//! - **String Interning**: Deduplicating identical string instances
//! - **Event Handlers**: Assembly and type resolution callbacks
//!
//! This module simulates these features to support accurate emulation of .NET code
//! that depends on runtime reflection or assembly loading behavior.
//!
//! # Note on Type System
//!
//! Type information (base types, interfaces, hierarchy) is handled by the
//! [`CilType`](crate::metadata::typesystem::CilType) in the metadata layer, accessed
//! via [`EmulationContext`](crate::emulation::engine::EmulationContext). This module
//! focuses on runtime-only concerns like dynamically loaded assemblies.
//!
//! # Key Types
//!
//! - [`AppDomainState`] - The main state container for the simulated AppDomain
//! - [`LoadedAssemblyInfo`] - Metadata about a loaded assembly
//!
//! # Examples
//!
//! ## Basic Usage
//!
//! The `examples::module_example` test in this module runs this example.
//!
//! # Use Cases
//!
//! ## Deobfuscation
//!
//! Many obfuscators dynamically load assemblies at runtime. The AppDomain
//! simulation tracks:
//!
//! - Dynamically loaded assemblies via `Assembly.Load(byte[])`
//! - Executing and entry assembly references
//! - AssemblyResolve event handler registration
//!
//! ## Runtime Behavior Emulation
//!
//! - String interning for comparison optimizations
//! - Assembly resolve events for plugin loading

use std::{collections::HashMap, sync::Arc};

use crate::{emulation::HeapRef, metadata::token::Token, CilObject};

/// Simulated application domain state.
///
/// This struct represents the runtime state of a .NET Application Domain (AppDomain),
/// providing storage and lookup facilities for assemblies, types, and interned strings.
/// It simulates key behaviors of the CLR's AppDomain class for emulation purposes.
///
/// # Overview
///
/// The `AppDomainState` maintains several key pieces of runtime information:
///
/// - **Loaded Assemblies**: Track which assemblies are available in the domain
/// - **Type Cache**: Map metadata tokens to runtime type information
/// - **String Intern Pool**: Deduplicate string instances for efficiency
/// - **Resolve Handlers**: Track callbacks for assembly/type resolution
/// - **Assembly References**: Track executing and entry assemblies
///
/// # Thread Safety
///
/// This type is not thread-safe. Access should be synchronized externally if
/// used from multiple threads.
///
/// # Examples
///
/// ```
/// use dotscope::emulation::AppDomainState;
/// use dotscope::metadata::token::Token;
///
/// let mut domain = AppDomainState::new();
///
/// // Set up the executing assembly
/// domain.set_executing_assembly(Token::new(0x20000001));
///
/// // The domain is ready for emulation
/// assert!(domain.executing_assembly().is_some());
/// ```
#[derive(Clone, Default)]
pub struct AppDomainState {
    /// Loaded assemblies indexed by their simple name.
    ///
    /// The key is the assembly's simple name (e.g., "mscorlib"), not the
    /// full assembly name with version and public key token.
    loaded_assemblies: HashMap<String, LoadedAssemblyInfo>,

    /// Pool of interned strings mapping string content to heap references.
    ///
    /// String interning ensures that identical string literals share the
    /// same heap allocation, matching .NET's runtime behavior.
    interned_strings: HashMap<String, HeapRef>,

    /// Registered handlers for the `AssemblyResolve` event.
    ///
    /// These are metadata tokens pointing to methods that should be invoked
    /// when an assembly cannot be resolved through normal means.
    assembly_resolve_handlers: Vec<Token>,

    /// Registered handlers for the `TypeResolve` event.
    ///
    /// These are metadata tokens pointing to methods that should be invoked
    /// when a type cannot be resolved through normal means.
    type_resolve_handlers: Vec<Token>,

    /// Token of the currently executing assembly.
    ///
    /// This corresponds to `Assembly.GetExecutingAssembly()` in .NET.
    executing_assembly: Option<Token>,

    /// Token of the application's entry assembly.
    ///
    /// This corresponds to `Assembly.GetEntryAssembly()` in .NET, which
    /// returns the assembly that contains the application's entry point.
    entry_assembly: Option<Token>,

    /// Parsed assemblies loaded at runtime via `Assembly.Load(byte[])`.
    ///
    /// Each entry is a fully parsed [`CilObject`] that can be used for
    /// metadata resolution and instruction fetching. The index into this
    /// vector is stored in [`ThreadCallFrame::assembly_index`](crate::emulation::ThreadCallFrame::assembly_index) to track
    /// which assembly a frame belongs to.
    loaded_cilobjects: Vec<Arc<CilObject>>,
}

impl std::fmt::Debug for AppDomainState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppDomainState")
            .field("loaded_assemblies", &self.loaded_assemblies)
            .field("interned_strings_count", &self.interned_strings.len())
            .field("assembly_resolve_handlers", &self.assembly_resolve_handlers)
            .field("type_resolve_handlers", &self.type_resolve_handlers)
            .field("executing_assembly", &self.executing_assembly)
            .field("entry_assembly", &self.entry_assembly)
            .field("loaded_cilobjects_count", &self.loaded_cilobjects.len())
            .finish()
    }
}

/// Information about a loaded assembly in the application domain.
///
/// This struct captures metadata about an assembly that has been loaded into
/// the emulated application domain. It mirrors the information available
/// through `System.Reflection.Assembly` properties in .NET.
///
/// # Examples
///
/// ```no_run
/// use dotscope::emulation::LoadedAssemblyInfo;
/// use dotscope::metadata::token::Token;
///
/// let info = LoadedAssemblyInfo {
///     name: "MyLibrary".to_string(),
///     token: Token::new(0x20000001),
///     full_name: Some("MyLibrary, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null".to_string()),
///     location: Some("/app/MyLibrary.dll".to_string()),
///     loaded_from_bytes: false,
/// };
/// ```
#[derive(Clone, Debug)]
pub struct LoadedAssemblyInfo {
    /// The simple name of the assembly (e.g., "mscorlib").
    ///
    /// This corresponds to `Assembly.GetName().Name` in .NET.
    pub name: String,

    /// The metadata token identifying this assembly in the emulation context.
    ///
    /// This is typically an Assembly table token (0x20xxxxxx).
    pub token: Token,

    /// The fully qualified assembly name including version and public key token.
    ///
    /// Format: "Name, Version=x.x.x.x, Culture=xxx, PublicKeyToken=xxx"
    /// This corresponds to `Assembly.FullName` in .NET.
    pub full_name: Option<String>,

    /// The file system path where the assembly was loaded from.
    ///
    /// This corresponds to `Assembly.Location` in .NET. Will be `None` for
    /// assemblies loaded from byte arrays or embedded resources.
    pub location: Option<String>,

    /// Indicates whether the assembly was loaded from a byte array.
    ///
    /// When `true`, the assembly was loaded via `Assembly.Load(byte[])` rather
    /// than from a file on disk. This affects the behavior of `Assembly.Location`.
    pub loaded_from_bytes: bool,
}

impl AppDomainState {
    /// Creates a new, empty application domain state.
    ///
    /// The new domain has no loaded assemblies and no resolve handlers.
    /// The executing and entry assemblies are not set.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use dotscope::emulation::AppDomainState;
    ///
    /// let domain = AppDomainState::new();
    /// assert!(domain.executing_assembly().is_none());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers an assembly as loaded in this application domain.
    ///
    /// The assembly is indexed by its simple name. If an assembly with the
    /// same name was previously registered, it will be replaced.
    ///
    /// # Arguments
    ///
    /// * `info` - Information about the assembly being registered
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use dotscope::emulation::AppDomainState;
    /// use dotscope::emulation::LoadedAssemblyInfo;
    /// use dotscope::metadata::token::Token;
    ///
    /// let mut domain = AppDomainState::new();
    /// domain.register_assembly(LoadedAssemblyInfo {
    ///     name: "TestAssembly".to_string(),
    ///     token: Token::new(0x20000001),
    ///     full_name: None,
    ///     location: None,
    ///     loaded_from_bytes: false,
    /// });
    /// ```
    pub fn register_assembly(&mut self, info: LoadedAssemblyInfo) {
        self.loaded_assemblies.insert(info.name.clone(), info);
    }

    /// Retrieves information about a loaded assembly by its simple name.
    ///
    /// # Arguments
    ///
    /// * `name` - The simple name of the assembly (e.g., "mscorlib")
    ///
    /// # Returns
    ///
    /// `Some(&LoadedAssemblyInfo)` if the assembly is loaded, `None` otherwise.
    #[must_use]
    pub fn get_assembly(&self, name: &str) -> Option<&LoadedAssemblyInfo> {
        self.loaded_assemblies.get(name)
    }

    /// Returns an iterator over all loaded assemblies in this domain.
    ///
    /// The iteration order is not guaranteed.
    ///
    /// # Examples
    ///
    /// ```
    /// # let domain = dotscope::emulation::AppDomainState::new();
    /// for assembly in domain.loaded_assemblies() {
    ///     println!("Loaded: {}", assembly.name);
    /// }
    /// ```
    pub fn loaded_assemblies(&self) -> impl Iterator<Item = &LoadedAssemblyInfo> {
        self.loaded_assemblies.values()
    }

    /// Sets the currently executing assembly.
    ///
    /// This should be updated as execution transitions between assemblies.
    /// The value is returned by stubs implementing `Assembly.GetExecutingAssembly()`.
    ///
    /// # Arguments
    ///
    /// * `token` - The metadata token of the assembly
    pub fn set_executing_assembly(&mut self, token: Token) {
        self.executing_assembly = Some(token);
    }

    /// Returns the token of the currently executing assembly.
    ///
    /// This corresponds to what `Assembly.GetExecutingAssembly()` would return
    /// in the emulated code.
    ///
    /// # Returns
    ///
    /// `Some(Token)` if an executing assembly has been set, `None` otherwise.
    #[must_use]
    pub fn executing_assembly(&self) -> Option<Token> {
        self.executing_assembly
    }

    /// Sets the entry assembly for this application domain.
    ///
    /// The entry assembly is the assembly containing the application's `Main`
    /// method or entry point. This is typically set once at the start of emulation.
    ///
    /// # Arguments
    ///
    /// * `token` - The metadata token of the entry assembly
    pub fn set_entry_assembly(&mut self, token: Token) {
        self.entry_assembly = Some(token);
    }

    /// Returns the token of the entry assembly.
    ///
    /// This corresponds to what `Assembly.GetEntryAssembly()` would return
    /// in the emulated code.
    ///
    /// # Returns
    ///
    /// `Some(Token)` if an entry assembly has been set, `None` otherwise.
    #[must_use]
    pub fn entry_assembly(&self) -> Option<Token> {
        self.entry_assembly
    }

    /// Interns a string, returning a heap reference to the canonical instance.
    ///
    /// String interning ensures that identical string values share the same
    /// heap allocation. If the string is already interned, the existing
    /// reference is returned and the provided `heap_ref` is not used.
    ///
    /// This mirrors the behavior of `String.Intern()` in .NET.
    ///
    /// # Arguments
    ///
    /// * `value` - The string content to intern
    /// * `heap_ref` - A heap reference to use if the string is not yet interned
    ///
    /// # Returns
    ///
    /// The heap reference to the interned string (either existing or new).
    ///
    /// # Examples
    ///
    /// ```
    /// use dotscope::emulation::{AppDomainState, HeapRef};
    ///
    /// let mut domain = AppDomainState::new();
    /// let ref1 = domain.intern_string("hello".to_string(), HeapRef::new(1));
    /// let ref2 = domain.intern_string("hello".to_string(), HeapRef::new(2));
    /// assert_eq!(ref1, ref2); // Same reference returned
    /// ```
    pub fn intern_string(&mut self, value: String, heap_ref: HeapRef) -> HeapRef {
        if let Some(&existing) = self.interned_strings.get(&value) {
            existing
        } else {
            self.interned_strings.insert(value, heap_ref);
            heap_ref
        }
    }

    /// Retrieves the heap reference for an interned string, if it exists.
    ///
    /// This mirrors the behavior of `String.IsInterned()` in .NET.
    ///
    /// # Arguments
    ///
    /// * `value` - The string content to look up
    ///
    /// # Returns
    ///
    /// `Some(HeapRef)` if the string is interned, `None` otherwise.
    #[must_use]
    pub fn get_interned(&self, value: &str) -> Option<HeapRef> {
        self.interned_strings.get(value).copied()
    }

    /// Adds a handler for the `AssemblyResolve` event.
    ///
    /// Assembly resolve handlers are invoked when an assembly reference
    /// cannot be resolved through normal means. The handler method should
    /// return an `Assembly` object or `null`.
    ///
    /// # Arguments
    ///
    /// * `handler` - Token of the handler method to register
    pub fn add_assembly_resolve_handler(&mut self, handler: Token) {
        self.assembly_resolve_handlers.push(handler);
    }

    /// Returns the registered `AssemblyResolve` event handlers.
    ///
    /// These handlers are invoked in registration order when assembly
    /// resolution fails.
    #[must_use]
    pub fn assembly_resolve_handlers(&self) -> &[Token] {
        &self.assembly_resolve_handlers
    }

    /// Adds a handler for the `TypeResolve` event.
    ///
    /// Type resolve handlers are invoked when a type reference cannot be
    /// resolved through normal means. The handler method should return
    /// a `Type` object or `null`.
    ///
    /// # Arguments
    ///
    /// * `handler` - Token of the handler method to register
    pub fn add_type_resolve_handler(&mut self, handler: Token) {
        self.type_resolve_handlers.push(handler);
    }

    /// Returns the registered `TypeResolve` event handlers.
    ///
    /// These handlers are invoked in registration order when type
    /// resolution fails.
    #[must_use]
    pub fn type_resolve_handlers(&self) -> &[Token] {
        &self.type_resolve_handlers
    }

    /// Registers a parsed assembly loaded at runtime (e.g., via `Assembly.Load(byte[])`).
    ///
    /// Returns the index of the newly registered assembly, which can be stored
    /// in [`ThreadCallFrame::assembly_index`](crate::emulation::ThreadCallFrame::assembly_index)
    /// to associate frames with their
    /// originating assembly.
    ///
    /// Returns `None` when the domain already holds `max` assemblies. Emulated code drives
    /// this list through `Assembly.Load(byte[])`, and each entry retains a whole parsed
    /// metadata graph in host memory that no heap budget accounts for, so the list has to be
    /// bounded by something. The caller decides what to do on refusal — the .NET-visible
    /// behaviour is a failed load, not a silently dropped registration.
    ///
    /// # Arguments
    ///
    /// * `asm` - The parsed [`CilObject`] wrapped in `Arc`
    /// * `max` - Maximum assemblies this domain may hold, from
    ///   [`EmulationLimits::max_loaded_assemblies`](crate::emulation::process::EmulationLimits::max_loaded_assemblies)
    pub fn register_parsed_assembly(&mut self, asm: Arc<CilObject>, max: usize) -> Option<usize> {
        if self.loaded_cilobjects.len() >= max {
            return None;
        }

        let index = self.loaded_cilobjects.len();
        self.loaded_cilobjects.push(asm);
        Some(index)
    }

    /// Retrieves a previously registered parsed assembly by index.
    ///
    /// # Arguments
    ///
    /// * `index` - The index returned by [`register_parsed_assembly`](Self::register_parsed_assembly)
    #[must_use]
    pub fn get_parsed_assembly(&self, index: usize) -> Option<&Arc<CilObject>> {
        self.loaded_cilobjects.get(index)
    }

    /// Searches all loaded assemblies for a type matching the given namespace and name.
    ///
    /// Returns the assembly index and type token if found. This enables
    /// cross-assembly type resolution for dynamically loaded assemblies.
    ///
    /// # Arguments
    ///
    /// * `namespace` - The type's namespace (e.g., "System.IO")
    /// * `name` - The type's name (e.g., "MemoryStream")
    #[must_use]
    pub fn find_type_across_assemblies(
        &self,
        namespace: &str,
        name: &str,
    ) -> Option<(usize, Token)> {
        for (index, asm) in self.loaded_cilobjects.iter().enumerate() {
            for cil_type in asm.types().all_types() {
                if cil_type.namespace == namespace && cil_type.name == name {
                    return Some((index, cil_type.token));
                }
            }
        }
        None
    }

    /// Returns the number of dynamically loaded parsed assemblies.
    #[must_use]
    pub fn parsed_assembly_count(&self) -> usize {
        self.loaded_cilobjects.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::fixture;

    #[test]
    fn test_app_domain_creation() {
        let domain = AppDomainState::new();
        assert!(domain.loaded_assemblies().next().is_none());
    }

    /// Loads the smallest sample available; only its identity as a parsed assembly matters.
    fn sample_assembly() -> Arc<CilObject> {
        let path = fixture("WindowsBase.dll");
        Arc::new(CilObject::from_path(&path).expect("sample assembly must load"))
    }

    /// Emulated code drives this list through `Assembly.Load(byte[])`, so it must refuse to
    /// grow past the configured limit rather than retain a parsed assembly per call.
    #[test]
    fn register_parsed_assembly_refuses_past_the_cap() {
        let mut domain = AppDomainState::new();
        let asm = sample_assembly();

        assert_eq!(
            domain.register_parsed_assembly(Arc::clone(&asm), 2),
            Some(0)
        );
        assert_eq!(
            domain.register_parsed_assembly(Arc::clone(&asm), 2),
            Some(1)
        );
        assert_eq!(domain.register_parsed_assembly(Arc::clone(&asm), 2), None);

        assert_eq!(domain.parsed_assembly_count(), 2);
    }

    /// A cap of zero must refuse everything rather than wrap into "unlimited".
    #[test]
    fn register_parsed_assembly_honours_a_zero_cap() {
        let mut domain = AppDomainState::new();

        assert_eq!(domain.register_parsed_assembly(sample_assembly(), 0), None);
        assert_eq!(domain.parsed_assembly_count(), 0);
    }

    /// Forks execute in parallel, so an assembly one fork loads must not appear in another —
    /// otherwise a planted type steers a sibling's method resolution.
    #[test]
    fn cloning_the_domain_keeps_later_registrations_local() {
        let mut parent = AppDomainState::new();
        parent.register_parsed_assembly(sample_assembly(), 8);

        let mut fork = parent.clone();
        fork.register_parsed_assembly(sample_assembly(), 8);

        assert_eq!(fork.parsed_assembly_count(), 2);
        assert_eq!(
            parent.parsed_assembly_count(),
            1,
            "a fork's load must not be visible to the parent"
        );
    }

    #[test]
    fn test_register_assembly() {
        let mut domain = AppDomainState::new();

        let info = LoadedAssemblyInfo {
            name: "TestAssembly".to_string(),
            token: Token::new(0x20000001),
            full_name: Some("TestAssembly, Version=1.0.0.0".to_string()),
            location: None,
            loaded_from_bytes: false,
        };

        domain.register_assembly(info);

        let loaded = domain.get_assembly("TestAssembly");
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().token, Token::new(0x20000001));
    }

    #[test]
    fn test_string_interning() {
        let mut domain = AppDomainState::new();

        let ref1 = HeapRef::new(1);
        let ref2 = HeapRef::new(2);

        // First intern
        let result1 = domain.intern_string("hello".to_string(), ref1);
        assert_eq!(result1, ref1);

        // Second intern should return same ref
        let result2 = domain.intern_string("hello".to_string(), ref2);
        assert_eq!(result2, ref1); // Returns original

        // Different string gets new ref
        let result3 = domain.intern_string("world".to_string(), ref2);
        assert_eq!(result3, ref2);
    }

    #[test]
    fn test_executing_assembly() {
        let mut domain = AppDomainState::new();

        assert!(domain.executing_assembly().is_none());

        domain.set_executing_assembly(Token::new(0x20000001));
        assert_eq!(domain.executing_assembly(), Some(Token::new(0x20000001)));
    }
}

#[cfg(test)]
mod examples {
    use super::*;
    use crate::{metadata::token::Token, Result};

    /// A registered assembly is found again by its name.
    #[test]
    fn module_example() -> Result<()> {
        let mut domain = AppDomainState::new();

        // Register an assembly
        domain.register_assembly(LoadedAssemblyInfo {
            name: "MyAssembly".to_string(),
            token: Token::new(0x20000001),
            full_name: Some("MyAssembly, Version=1.0.0.0".to_string()),
            location: Some("/path/to/assembly.dll".to_string()),
            loaded_from_bytes: false,
        });

        // Query the assembly
        let info = domain.get_assembly("MyAssembly").expect("registered");
        assert_eq!(
            info.full_name.as_deref(),
            Some("MyAssembly, Version=1.0.0.0")
        );
        assert!(domain.get_assembly("Other").is_none());
        Ok(())
    }
}
