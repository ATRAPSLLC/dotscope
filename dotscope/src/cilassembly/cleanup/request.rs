//! Cleanup request specification for assembly modifications.
//!
//! This module defines [`CleanupRequest`], which specifies what metadata entries
//! should be removed from an assembly. The cleanup executor will process this
//! request and remove the specified items along with any orphaned metadata that
//! becomes unreferenced as a result.

use std::collections::{BTreeSet, HashSet};

use crate::metadata::{tables::TableId, token::Token};

/// Request for cleanup operations on a [`CilAssembly`](crate::CilAssembly).
///
/// Specifies explicit deletions to perform. The cleanup executor will:
///
/// 1. Apply these explicit deletions
/// 2. Find and remove orphaned metadata caused by these deletions
/// 3. **Not** remove pre-existing orphans (to preserve intentional patterns)
///
/// This distinction is important: we only remove metadata that became orphaned
/// due to our changes, not metadata that was already orphaned in the original
/// assembly (which may be used via reflection or dynamic code).
///
/// # Iterator Access
///
/// The accessor methods (`types()`, `methods()`, etc.) return iterators that
/// yield tokens in descending RID order. This is the correct order for deletion
/// operations to avoid RID shifting issues.
///
/// # Example
///
/// ```no_run
/// use dotscope::CleanupRequest;
///
/// let mut request = CleanupRequest::default();
/// request.add_type(protection_type_token);
/// request.add_method(decryptor_method_token);
/// request.exclude_section(".confuser");
///
/// // Iterate in descending order for safe deletion
/// for token in request.types() {
///     // tokens come in descending RID order
/// }
/// ```
#[derive(Debug, Clone)]
pub struct CleanupRequest {
    /// TypeDef tokens to remove.
    ///
    /// When a type is removed, all its members (methods, fields, properties,
    /// events) are also removed, along with cascading orphaned metadata.
    types: BTreeSet<Token>,

    /// MethodDef tokens to remove.
    ///
    /// Removing a method also removes its parameters, local variable signatures,
    /// and any metadata entries that reference only this method.
    methods: BTreeSet<Token>,

    /// MethodSpec tokens to remove.
    ///
    /// Generic method instantiations (e.g., `Decryptor<string>.Decrypt()`).
    methodspecs: BTreeSet<Token>,

    /// Field tokens to remove.
    ///
    /// Removing a field also removes associated FieldRVA, FieldLayout,
    /// FieldMarshal, and Constant entries.
    fields: BTreeSet<Token>,

    /// CustomAttribute tokens to remove directly.
    ///
    /// These are removed without checking if they're orphaned.
    attributes: BTreeSet<Token>,

    /// AssemblyRef tokens to remove.
    ///
    /// External assembly references that are no longer needed after
    /// protection infrastructure is removed (e.g., `System.Private.CoreLib`
    /// added by BitMono AntiDebug, fake references added by ConfuserEx).
    assemblyrefs: BTreeSet<Token>,

    /// ModuleRef tokens to remove.
    ///
    /// External module references (native DLLs) that are no longer needed
    /// after P/Invoke-based protection methods are removed (e.g., `kernel32.dll`
    /// used by anti-tamper, `libc.so.6` used by DotNetHook).
    modulerefs: BTreeSet<Token>,

    /// ManifestResource tokens to remove.
    ///
    /// Used for NR-injected encrypted resources (anti-tamper, string tables,
    /// etc.) whose backing data is embedded in the PE's CLR resource
    /// section. The generic orphan sweep only removes rows whose
    /// implementation target (File / AssemblyRef) has been deleted — it
    /// can't reach embedded rows (`implementation.row == 0`). The writer
    /// honours deleted-row marks by compacting the resource section and
    /// remapping `offset_field` values on surviving rows, so once a row is
    /// marked deleted here the executor's `try_remove` wiring is all that's
    /// needed; the embedded bytes vanish automatically during regeneration.
    manifest_resources: BTreeSet<Token>,

    /// Metadata tokens orphaned by SSA body rewriting (not entity deletion).
    /// These become additional cascade candidates for MemberRef/TypeRef/AssemblyRef removal.
    rewrite_orphaned_tokens: HashSet<Token>,

    /// PE sections to exclude from output.
    ///
    /// Section names (e.g., ".confuser", ".packed") that should not be
    /// included in the generated assembly. Useful for removing obfuscator
    /// artifact sections that contain encrypted data.
    excluded_sections: HashSet<String>,

    /// Whether to remove orphaned metadata entries.
    ///
    /// When true (default), metadata entries that reference only deleted
    /// items will be removed. When false, only explicit deletions are applied.
    remove_orphans: bool,

    /// Whether to remove types that become empty after cleanup.
    ///
    /// When true, types with no remaining methods or fields after cleanup
    /// are also removed.
    remove_empty_types: bool,

    /// Tokens that must not be deleted by any cleanup phase.
    ///
    /// Protected tokens are exempt from explicit deletion, cascade removal,
    /// and empty-type elimination. This is used to preserve metadata entries
    /// created by code generation (e.g., FieldDef + TypeDef entries for
    /// `RuntimeHelpers.InitializeArray` patterns) that would otherwise be
    /// removed as orphans because they were created after the cleanup request
    /// was built.
    protected_tokens: HashSet<Token>,

    /// Methods removed together with every call to them.
    ///
    /// A protection check - a trial expiry, an anti-debug probe - is called
    /// from the program's own methods only because the protector put the call
    /// there. Removing the method is half of removing the protection; the
    /// calls go too, which neutralization does. Every other removal is of code
    /// nothing should still call, and one that surviving code does call is
    /// withdrawn instead.
    call_sites_stripped: BTreeSet<Token>,
}

impl Default for CleanupRequest {
    fn default() -> Self {
        Self {
            types: BTreeSet::new(),
            methods: BTreeSet::new(),
            methodspecs: BTreeSet::new(),
            fields: BTreeSet::new(),
            attributes: BTreeSet::new(),
            assemblyrefs: BTreeSet::new(),
            modulerefs: BTreeSet::new(),
            manifest_resources: BTreeSet::new(),
            rewrite_orphaned_tokens: HashSet::new(),
            excluded_sections: HashSet::new(),
            remove_orphans: true,
            remove_empty_types: true,
            protected_tokens: HashSet::new(),
            call_sites_stripped: BTreeSet::new(),
        }
    }
}

impl CleanupRequest {
    /// Creates a new cleanup request with default settings.
    ///
    /// Default settings:
    /// - `remove_orphans`: true
    /// - `remove_empty_types`: true
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a cleanup request with custom settings.
    #[must_use]
    pub fn with_settings(remove_orphans: bool, remove_empty_types: bool) -> Self {
        Self {
            remove_orphans,
            remove_empty_types,
            ..Self::default()
        }
    }

    /// Adds a type (TypeDef) to be removed.
    ///
    /// When a type is removed, its methods and fields will also be removed,
    /// along with any orphaned metadata entries that reference it.
    pub fn add_type(&mut self, token: Token) -> &mut Self {
        self.types.insert(token);
        self
    }

    /// Adds multiple types (TypeDef) to be removed.
    pub fn add_types(&mut self, tokens: impl IntoIterator<Item = Token>) -> &mut Self {
        self.types.extend(tokens);
        self
    }

    /// Returns an iterator over types to remove in descending RID order.
    ///
    /// This ordering is required for safe deletion to avoid RID shifting issues.
    pub fn types(&self) -> impl Iterator<Item = &Token> + '_ {
        self.types.iter().rev()
    }

    /// Returns the number of types to remove.
    #[must_use]
    pub fn types_len(&self) -> usize {
        self.types.len()
    }

    /// Adds a method (MethodDef) to be removed.
    pub fn add_method(&mut self, token: Token) -> &mut Self {
        self.methods.insert(token);
        self
    }

    /// Adds multiple methods (MethodDef) to be removed.
    pub fn add_methods(&mut self, tokens: impl IntoIterator<Item = Token>) -> &mut Self {
        self.methods.extend(tokens);
        self
    }

    /// Adds a protection method (MethodDef) to be removed together with every
    /// call to it.
    ///
    /// For a method the program calls only because a protector inserted the
    /// call - a trial check, an anti-debug probe. Its call sites in converted
    /// methods are stripped by neutralization rather than keeping the method
    /// alive, which is what a call from surviving code does to any other
    /// removal.
    pub fn add_protection_method(&mut self, token: Token) -> &mut Self {
        self.methods.insert(token);
        self.call_sites_stripped.insert(token);
        self
    }

    /// Whether the calls to `token` are removed with it (see
    /// [`Self::add_protection_method`]).
    #[must_use]
    pub fn strips_call_sites(&self, token: Token) -> bool {
        self.call_sites_stripped.contains(&token)
    }

    /// Returns an iterator over methods to remove in descending RID order.
    ///
    /// This ordering is required for safe deletion to avoid RID shifting issues.
    pub fn methods(&self) -> impl Iterator<Item = &Token> + '_ {
        self.methods.iter().rev()
    }

    /// Returns the number of methods to remove.
    #[must_use]
    pub fn methods_len(&self) -> usize {
        self.methods.len()
    }

    /// Adds a MethodSpec to be removed.
    pub fn add_methodspec(&mut self, token: Token) -> &mut Self {
        self.methodspecs.insert(token);
        self
    }

    /// Adds multiple MethodSpecs to be removed.
    pub fn add_methodspecs(&mut self, tokens: impl IntoIterator<Item = Token>) -> &mut Self {
        self.methodspecs.extend(tokens);
        self
    }

    /// Returns an iterator over MethodSpecs to remove in descending RID order.
    ///
    /// This ordering is required for safe deletion to avoid RID shifting issues.
    pub fn methodspecs(&self) -> impl Iterator<Item = &Token> + '_ {
        self.methodspecs.iter().rev()
    }

    /// Returns the number of MethodSpecs to remove.
    #[must_use]
    pub fn methodspecs_len(&self) -> usize {
        self.methodspecs.len()
    }

    /// Adds a field to be removed.
    ///
    /// Non-Field tokens (e.g. MemberRef referencing an external field) are
    /// dropped with a warning. The cleanup pipeline can only remove rows from
    /// the local Field table; foreign references should reach cleanup via the
    /// orphan cascade, not via direct deletion. Smuggling a MemberRef in here
    /// would be misinterpreted as `Field RID == memberref.row`, which has
    /// historically corrupted the Field table row count.
    pub fn add_field(&mut self, token: Token) -> &mut Self {
        if !token.is_table(TableId::Field) {
            log::warn!(
                "CleanupRequest::add_field rejected non-Field token {token:?} \
                 (only FieldDef rows are deletable here)"
            );
            return self;
        }
        self.fields.insert(token);
        self
    }

    /// Adds multiple fields to be removed.
    ///
    /// See [`Self::add_field`] for the table-id constraint; non-Field tokens
    /// are dropped with a warning instead of being inserted.
    pub fn add_fields(&mut self, tokens: impl IntoIterator<Item = Token>) -> &mut Self {
        for tok in tokens {
            self.add_field(tok);
        }
        self
    }

    /// Returns an iterator over fields to remove in descending RID order.
    ///
    /// This ordering is required for safe deletion to avoid RID shifting issues.
    pub fn fields(&self) -> impl Iterator<Item = &Token> + '_ {
        self.fields.iter().rev()
    }

    /// Returns the number of fields to remove.
    #[must_use]
    pub fn fields_len(&self) -> usize {
        self.fields.len()
    }

    /// Takes back a scheduled removal, whatever kind of token it is.
    ///
    /// A request is assembled by several independent producers, each deciding
    /// from the snapshot of deletions that existed when it ran. Soundness is a
    /// property of the finished request rather than of any one of them - no
    /// surviving code may name a token the request removes - so the builder
    /// needs to be able to retract a decision once the whole is visible.
    ///
    /// Withdrawing a type resurrects its members with it, since membership is
    /// what put them in the removal set.
    ///
    /// # Arguments
    ///
    /// * `token` - The token to stop removing.
    ///
    /// # Returns
    ///
    /// `true` when the token was scheduled for removal and no longer is.
    pub fn withdraw(&mut self, token: Token) -> bool {
        self.types.remove(&token)
            | self.methods.remove(&token)
            | self.methodspecs.remove(&token)
            | self.fields.remove(&token)
            | self.attributes.remove(&token)
            | self.assemblyrefs.remove(&token)
            | self.modulerefs.remove(&token)
            | self.manifest_resources.remove(&token)
    }

    /// Adds a custom attribute to be removed.
    pub fn add_attribute(&mut self, token: Token) -> &mut Self {
        self.attributes.insert(token);
        self
    }

    /// Adds multiple custom attributes to be removed.
    pub fn add_attributes(&mut self, tokens: impl IntoIterator<Item = Token>) -> &mut Self {
        self.attributes.extend(tokens);
        self
    }

    /// Returns an iterator over attributes to remove in descending RID order.
    ///
    /// This ordering is required for safe deletion to avoid RID shifting issues.
    pub fn attributes(&self) -> impl Iterator<Item = &Token> + '_ {
        self.attributes.iter().rev()
    }

    /// Returns the number of attributes to remove.
    #[must_use]
    pub fn attributes_len(&self) -> usize {
        self.attributes.len()
    }

    /// Adds an AssemblyRef to be removed.
    pub fn add_assemblyref(&mut self, token: Token) -> &mut Self {
        self.assemblyrefs.insert(token);
        self
    }

    /// Adds multiple AssemblyRefs to be removed.
    pub fn add_assemblyrefs(&mut self, tokens: impl IntoIterator<Item = Token>) -> &mut Self {
        self.assemblyrefs.extend(tokens);
        self
    }

    /// Returns an iterator over AssemblyRefs to remove in descending RID order.
    pub fn assemblyrefs(&self) -> impl Iterator<Item = &Token> + '_ {
        self.assemblyrefs.iter().rev()
    }

    /// Returns the number of AssemblyRefs to remove.
    #[must_use]
    pub fn assemblyrefs_len(&self) -> usize {
        self.assemblyrefs.len()
    }

    /// Adds a ModuleRef to be removed.
    pub fn add_moduleref(&mut self, token: Token) -> &mut Self {
        self.modulerefs.insert(token);
        self
    }

    /// Adds multiple ModuleRefs to be removed.
    pub fn add_modulerefs(&mut self, tokens: impl IntoIterator<Item = Token>) -> &mut Self {
        self.modulerefs.extend(tokens);
        self
    }

    /// Returns an iterator over ModuleRefs to remove in descending RID order.
    pub fn modulerefs(&self) -> impl Iterator<Item = &Token> + '_ {
        self.modulerefs.iter().rev()
    }

    /// Returns the number of ModuleRefs to remove.
    #[must_use]
    pub fn modulerefs_len(&self) -> usize {
        self.modulerefs.len()
    }

    /// Adds a `ManifestResource` row to be removed.
    ///
    /// Accepts both `Token(TableId::ManifestResource, rid)` and plain RID
    /// tokens — the executor normalises on RID. The corresponding embedded
    /// bytes (for rows whose `implementation.row == 0`) are dropped during
    /// PE regeneration because the writer's existing compaction loop
    /// already respects `is_row_deleted(TableId::ManifestResource, rid)`.
    pub fn add_manifest_resource(&mut self, token: Token) -> &mut Self {
        self.manifest_resources.insert(token);
        self
    }

    /// Adds multiple `ManifestResource` rows to be removed.
    pub fn add_manifest_resources(&mut self, tokens: impl IntoIterator<Item = Token>) -> &mut Self {
        self.manifest_resources.extend(tokens);
        self
    }

    /// Returns an iterator over `ManifestResource` rows to remove in
    /// descending RID order (required for safe row removal).
    pub fn manifest_resources(&self) -> impl Iterator<Item = &Token> + '_ {
        self.manifest_resources.iter().rev()
    }

    /// Returns the number of `ManifestResource` rows to remove.
    #[must_use]
    pub fn manifest_resources_len(&self) -> usize {
        self.manifest_resources.len()
    }

    /// Adds metadata tokens orphaned by SSA body rewriting as cascade candidates.
    pub fn add_rewrite_orphaned_tokens(
        &mut self,
        tokens: impl IntoIterator<Item = Token>,
    ) -> &mut Self {
        self.rewrite_orphaned_tokens.extend(tokens);
        self
    }

    /// Returns the set of rewrite-orphaned tokens.
    #[must_use]
    pub fn rewrite_orphaned_tokens(&self) -> &HashSet<Token> {
        &self.rewrite_orphaned_tokens
    }

    /// Excludes a PE section from output.
    ///
    /// The section name should include the dot prefix (e.g., ".confuser").
    pub fn exclude_section(&mut self, name: impl Into<String>) -> &mut Self {
        self.excluded_sections.insert(name.into());
        self
    }

    /// Excludes multiple PE sections from output.
    pub fn exclude_sections(&mut self, names: impl IntoIterator<Item = String>) -> &mut Self {
        self.excluded_sections.extend(names);
        self
    }

    /// Returns the set of sections to exclude.
    #[must_use]
    pub fn excluded_sections(&self) -> &HashSet<String> {
        &self.excluded_sections
    }

    /// Sets whether to remove orphaned metadata.
    pub fn set_remove_orphans(&mut self, remove: bool) -> &mut Self {
        self.remove_orphans = remove;
        self
    }

    /// Returns whether orphaned metadata will be removed.
    #[must_use]
    pub fn remove_orphans(&self) -> bool {
        self.remove_orphans
    }

    /// Sets whether to remove empty types after cleanup.
    pub fn set_remove_empty_types(&mut self, remove: bool) -> &mut Self {
        self.remove_empty_types = remove;
        self
    }

    /// Returns whether empty types will be removed.
    #[must_use]
    pub fn remove_empty_types(&self) -> bool {
        self.remove_empty_types
    }

    /// Marks a token as protected from all cleanup phases.
    ///
    /// Protected tokens will not be deleted by explicit deletion, cascade
    /// removal, or empty-type elimination. Use this for metadata entries
    /// created by code generation that must survive cleanup.
    pub fn protect_token(&mut self, token: Token) -> &mut Self {
        self.protected_tokens.insert(token);
        self
    }

    /// Marks multiple tokens as protected from all cleanup phases.
    pub fn protect_tokens(&mut self, tokens: impl IntoIterator<Item = Token>) -> &mut Self {
        self.protected_tokens.extend(tokens);
        self
    }

    /// Returns whether a token is protected from cleanup.
    #[must_use]
    pub fn is_protected(&self, token: Token) -> bool {
        self.protected_tokens.contains(&token)
    }

    /// Returns true if this request has no deletions or modifications specified.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
            && self.methods.is_empty()
            && self.methodspecs.is_empty()
            && self.fields.is_empty()
            && self.attributes.is_empty()
            && self.assemblyrefs.is_empty()
            && self.modulerefs.is_empty()
            && self.manifest_resources.is_empty()
            && self.excluded_sections.is_empty()
            && self.rewrite_orphaned_tokens.is_empty()
    }

    /// Returns true if this request has any deletions specified.
    #[must_use]
    pub fn has_deletions(&self) -> bool {
        !self.is_empty()
    }

    /// Returns the total count of items to delete.
    #[must_use]
    pub fn deletion_count(&self) -> usize {
        self.types
            .len()
            .saturating_add(self.methods.len())
            .saturating_add(self.methodspecs.len())
            .saturating_add(self.fields.len())
            .saturating_add(self.attributes.len())
            .saturating_add(self.assemblyrefs.len())
            .saturating_add(self.modulerefs.len())
            .saturating_add(self.manifest_resources.len())
    }

    /// Checks if a specific token is marked for deletion.
    ///
    /// This checks all token sets (types, methods, methodspecs, fields, attributes).
    /// Protected tokens are never considered deleted.
    #[must_use]
    pub fn is_deleted(&self, token: Token) -> bool {
        if self.protected_tokens.contains(&token) {
            return false;
        }
        self.types.contains(&token)
            || self.methods.contains(&token)
            || self.methodspecs.contains(&token)
            || self.fields.contains(&token)
            || self.attributes.contains(&token)
            || self.assemblyrefs.contains(&token)
            || self.modulerefs.contains(&token)
            || self.manifest_resources.contains(&token)
    }

    /// Adds methods from a `boxcar::Vec<Token>`.
    ///
    /// Convenience helper for the common pattern of iterating a boxcar detection
    /// collection and inserting each token into the methods set.
    pub fn add_methods_from(&mut self, tokens: &boxcar::Vec<Token>) -> &mut Self {
        for (_, token) in tokens {
            self.methods.insert(*token);
        }
        self
    }

    /// Adds types from a `boxcar::Vec<Token>`.
    pub fn add_types_from(&mut self, tokens: &boxcar::Vec<Token>) -> &mut Self {
        for (_, token) in tokens {
            self.types.insert(*token);
        }
        self
    }

    /// Adds fields from a `boxcar::Vec<Token>`.
    ///
    /// Honours the same FieldDef-only constraint as [`Self::add_field`].
    pub fn add_fields_from(&mut self, tokens: &boxcar::Vec<Token>) -> &mut Self {
        for (_, token) in tokens {
            self.add_field(*token);
        }
        self
    }

    /// Adds attributes from a `boxcar::Vec<Token>`.
    pub fn add_attributes_from(&mut self, tokens: &boxcar::Vec<Token>) -> &mut Self {
        for (_, token) in tokens {
            self.attributes.insert(*token);
        }
        self
    }

    /// Narrows this request's settings to what `other` allows as well: a cleanup gathered
    /// from several requests removes orphans, or empty types, only when every one of them
    /// asks for it.
    pub(crate) fn narrow_settings(&mut self, other: &CleanupRequest) {
        self.remove_orphans &= other.remove_orphans;
        self.remove_empty_types &= other.remove_empty_types;
    }

    /// Merges another cleanup request into this one.
    ///
    /// All tokens from `other` are added to this request.
    /// Settings (`remove_orphans`, `remove_empty_types`) are not changed.
    pub fn merge(&mut self, other: &CleanupRequest) -> &mut Self {
        self.types.extend(other.types.iter().copied());
        self.methods.extend(other.methods.iter().copied());
        self.methodspecs.extend(other.methodspecs.iter().copied());
        self.fields.extend(other.fields.iter().copied());
        self.attributes.extend(other.attributes.iter().copied());
        self.assemblyrefs.extend(other.assemblyrefs.iter().copied());
        self.modulerefs.extend(other.modulerefs.iter().copied());
        self.manifest_resources
            .extend(other.manifest_resources.iter().copied());
        self.rewrite_orphaned_tokens
            .extend(other.rewrite_orphaned_tokens.iter().copied());
        self.excluded_sections
            .extend(other.excluded_sections.iter().cloned());
        self.protected_tokens
            .extend(other.protected_tokens.iter().copied());
        self.call_sites_stripped
            .extend(other.call_sites_stripped.iter().copied());
        self
    }

    /// Returns all tokens scheduled for removal.
    ///
    /// This includes types, methods, methodspecs, fields, and attributes.
    #[must_use]
    pub fn all_tokens(&self) -> HashSet<Token> {
        let mut all = HashSet::new();
        all.extend(&self.types);
        all.extend(&self.methods);
        all.extend(&self.methodspecs);
        all.extend(&self.fields);
        all.extend(&self.attributes);
        all.extend(&self.assemblyrefs);
        all.extend(&self.modulerefs);
        all.extend(&self.manifest_resources);
        all
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        cilassembly::cleanup::CleanupRequest,
        metadata::{tables::TableId, token::Token},
    };

    #[test]
    fn test_cleanup_request_default() {
        let request = CleanupRequest::default();
        assert!(request.is_empty());
        assert!(!request.has_deletions());
        assert_eq!(request.deletion_count(), 0);
        assert!(request.remove_orphans());
        assert!(request.remove_empty_types());
    }

    #[test]
    fn test_add_type() {
        let mut request = CleanupRequest::new();
        let token = Token::from_parts(TableId::TypeDef, 5);

        request.add_type(token);

        assert!(!request.is_empty());
        assert!(request.has_deletions());
        assert_eq!(request.deletion_count(), 1);
        assert!(request.is_deleted(token));
        assert_eq!(request.types_len(), 1);
    }

    #[test]
    fn test_add_method() {
        let mut request = CleanupRequest::new();
        let token = Token::from_parts(TableId::MethodDef, 10);

        request.add_method(token);

        assert!(request.is_deleted(token));
        assert_eq!(request.methods_len(), 1);
    }

    #[test]
    fn test_exclude_section() {
        let mut request = CleanupRequest::new();

        request.exclude_section(".confuser");
        request.exclude_section(".packed");

        assert_eq!(request.excluded_sections().len(), 2);
        assert!(request.excluded_sections().contains(".confuser"));
        assert!(request.excluded_sections().contains(".packed"));
    }

    #[test]
    fn test_merge() {
        let mut request1 = CleanupRequest::new();
        request1.add_type(Token::from_parts(TableId::TypeDef, 1));

        let mut request2 = CleanupRequest::new();
        request2.add_method(Token::from_parts(TableId::MethodDef, 2));
        request2.exclude_section(".test");

        request1.merge(&request2);

        assert_eq!(request1.deletion_count(), 2);
        assert!(request1.excluded_sections().contains(".test"));
    }

    #[test]
    fn test_with_settings() {
        let request = CleanupRequest::with_settings(false, false);

        assert!(!request.remove_orphans());
        assert!(!request.remove_empty_types());
    }

    #[test]
    fn test_method_chaining() {
        let token1 = Token::from_parts(TableId::TypeDef, 1);
        let token2 = Token::from_parts(TableId::MethodDef, 2);
        let token3 = Token::from_parts(TableId::Field, 3);

        let mut request = CleanupRequest::new();
        request
            .add_type(token1)
            .add_method(token2)
            .add_field(token3)
            .exclude_section(".data")
            .set_remove_orphans(true);

        assert_eq!(request.deletion_count(), 3);
        assert!(request.excluded_sections().contains(".data"));
    }

    #[test]
    fn test_types_iterator_descending_order() {
        let mut request = CleanupRequest::new();
        request.add_type(Token::from_parts(TableId::TypeDef, 1));
        request.add_type(Token::from_parts(TableId::TypeDef, 5));
        request.add_type(Token::from_parts(TableId::TypeDef, 3));

        let tokens: Vec<&Token> = request.types().collect();

        // Should be in descending order: 5, 3, 1
        assert_eq!(tokens.len(), 3);
        assert_eq!(tokens[0].row(), 5);
        assert_eq!(tokens[1].row(), 3);
        assert_eq!(tokens[2].row(), 1);
    }

    #[test]
    fn test_methods_iterator_descending_order() {
        let mut request = CleanupRequest::new();
        request.add_method(Token::from_parts(TableId::MethodDef, 10));
        request.add_method(Token::from_parts(TableId::MethodDef, 2));
        request.add_method(Token::from_parts(TableId::MethodDef, 7));

        let tokens: Vec<&Token> = request.methods().collect();

        // Should be in descending order: 10, 7, 2
        assert_eq!(tokens.len(), 3);
        assert_eq!(tokens[0].row(), 10);
        assert_eq!(tokens[1].row(), 7);
        assert_eq!(tokens[2].row(), 2);
    }
}
