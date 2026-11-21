//! Technique registry for managing available deobfuscation techniques.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::deobfuscation::techniques::{
    bitmono::{
        BitMonoAntiDebug, BitMonoCalli, BitMonoHooks, BitMonoJunk, BitMonoLocals, BitMonoNops,
        BitMonoPeRepair, BitMonoRenamer, BitMonoStrings, BitMonoTokens, BitMonoUnmanaged,
    },
    confuserex::{
        ConfuserExAntiDebug, ConfuserExAntiDump, ConfuserExAntiTamper, ConfuserExConstants,
        ConfuserExMarker, ConfuserExMetadata, ConfuserExNativeHelpers, ConfuserExReferenceProxy,
        ConfuserExResources,
    },
    generic::{
        GenericAntiDebug, GenericAntiDump, GenericConstants, GenericDecompiler,
        GenericDelegateProxy, GenericFlattening, GenericHandlers, GenericIldasm, GenericMetadata,
        GenericOpaquePredicates, GenericStrings,
    },
    jiejienet::{
        JiejieNetArrays, JiejieNetConstants, JiejieNetResources, JiejieNetStrings, JiejieNetTypeOf,
    },
    netreactor::{
        NetReactorAntiTamp, NetReactorAntiTrial, NetReactorEmptyResource, NetReactorLicenseCheck,
        NetReactorNecroBit, NetReactorPrivateImpl, NetReactorResources,
    },
    obfuscar::ObfuscarStrings,
    AttributionResult, Detections, Technique,
};

/// Defines the set of techniques required to attribute an obfuscator.
///
/// An obfuscator is attributed when every technique listed in `required` is
/// detected. The `supporting` list contains additional techniques that
/// strengthen the match and are used for ranking when multiple obfuscators
/// could be attributed.
pub struct ObfuscatorSignature {
    /// Obfuscator name returned in [`AttributionResult`].
    pub name: &'static str,
    /// Technique IDs that must **all** be detected for attribution.
    pub required: Vec<&'static str>,
    /// Technique IDs that boost ranking when also detected.
    pub supporting: Vec<&'static str>,
}

/// Registry of all available deobfuscation techniques.
///
/// All techniques are stored in a single list regardless of whether they
/// perform byte transforms, SSA passes, or both. The registry provides
/// topological sorting for execution order based on `requires()` and
/// `supersedes()` declarations.
///
/// Attribution logic (matching detections to known obfuscator signatures) is
/// handled by the separate [`ObfuscatorMatcher`].
pub struct TechniqueRegistry {
    techniques: Vec<Box<dyn Technique>>,
}

impl TechniqueRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            techniques: Vec::new(),
        }
    }

    /// Creates a registry pre-populated with all built-in techniques.
    ///
    /// # Byte-capable techniques
    ///
    /// Generic:     metadata, ildasm, handlers, decompiler
    /// ConfuserEx:  marker, metadata, tamper, resources, natives
    /// BitMono:     pe, tokens, hooks, junk
    /// JIEJIE.NET:  arrays, resources
    /// .NET Reactor: necrobit, resources
    ///
    /// # SSA-capable techniques
    ///
    /// Generic:     flattening, strings, constants, debug, dump, opaquefields, delegates
    /// ConfuserEx:  constants, debug, dump
    /// BitMono:     strings, unmanaged, debug, nops, renamer, locals
    /// JIEJIE.NET:  constants, strings, typeof, arrays, resources
    /// Obfuscar:    strings
    /// .NET Reactor: antitamp, resources
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::with_config(50_000)
    }

    /// Creates a registry pre-populated with all built-in techniques
    /// using the given configuration values.
    #[must_use]
    pub fn with_config(nop_threshold: usize) -> Self {
        let mut registry = Self::new();

        // Generic techniques
        registry.register(Box::new(GenericMetadata));
        registry.register(Box::new(GenericIldasm));
        registry.register(Box::new(GenericHandlers));
        registry.register(Box::new(GenericDecompiler));
        registry.register(Box::new(GenericFlattening));
        registry.register(Box::new(GenericStrings));
        registry.register(Box::new(GenericConstants));
        registry.register(Box::new(GenericAntiDebug));
        registry.register(Box::new(GenericAntiDump));
        registry.register(Box::new(GenericOpaquePredicates));
        registry.register(Box::new(GenericDelegateProxy));

        // ConfuserEx techniques
        registry.register(Box::new(ConfuserExMarker));
        registry.register(Box::new(ConfuserExMetadata));
        registry.register(Box::new(ConfuserExAntiTamper));
        registry.register(Box::new(ConfuserExResources));
        registry.register(Box::new(ConfuserExNativeHelpers));
        registry.register(Box::new(ConfuserExConstants));
        registry.register(Box::new(ConfuserExReferenceProxy));
        registry.register(Box::new(ConfuserExAntiDebug));
        registry.register(Box::new(ConfuserExAntiDump));

        // BitMono techniques
        registry.register(Box::new(BitMonoPeRepair));
        registry.register(Box::new(BitMonoTokens));
        registry.register(Box::new(BitMonoHooks));
        registry.register(Box::new(BitMonoJunk));
        registry.register(Box::new(BitMonoLocals));
        registry.register(Box::new(BitMonoCalli));
        registry.register(Box::new(BitMonoStrings));
        registry.register(Box::new(BitMonoUnmanaged));
        registry.register(Box::new(BitMonoAntiDebug));
        registry.register(Box::new(BitMonoNops::new(nop_threshold)));
        registry.register(Box::new(BitMonoRenamer));

        // JIEJIE.NET techniques
        registry.register(Box::new(JiejieNetConstants));
        registry.register(Box::new(JiejieNetStrings));
        registry.register(Box::new(JiejieNetTypeOf));
        registry.register(Box::new(JiejieNetArrays));
        registry.register(Box::new(JiejieNetResources));

        // Obfuscar techniques
        registry.register(Box::new(ObfuscarStrings));

        // .NET Reactor techniques
        registry.register(Box::new(NetReactorNecroBit));
        registry.register(Box::new(NetReactorAntiTrial));
        registry.register(Box::new(NetReactorAntiTamp));
        registry.register(Box::new(NetReactorLicenseCheck));
        registry.register(Box::new(NetReactorEmptyResource));
        registry.register(Box::new(NetReactorPrivateImpl));
        registry.register(Box::new(NetReactorResources));

        registry
    }

    /// Registers a technique.
    ///
    /// # Arguments
    ///
    /// * `technique` - Boxed [`Technique`] implementation to register.
    pub fn register(&mut self, technique: Box<dyn Technique>) {
        self.techniques.push(technique);
    }

    /// Returns all registered techniques.
    ///
    /// # Returns
    ///
    /// A slice of all techniques in registration order.
    #[must_use]
    pub fn techniques(&self) -> &[Box<dyn Technique>] {
        &self.techniques
    }

    /// Returns `true` if any techniques are registered.
    #[must_use]
    pub fn has_techniques(&self) -> bool {
        !self.techniques.is_empty()
    }

    /// Returns techniques sorted by dependency order, filtered by supersedes.
    ///
    /// Uses Kahn's algorithm (topological sort) to order techniques so that
    /// every technique's `requires()` dependencies appear before it. Techniques
    /// superseded by a currently-detected technique are excluded entirely.
    ///
    /// If a dependency cycle is detected, the remaining techniques are appended
    /// in arbitrary order with a warning.
    ///
    /// # Arguments
    ///
    /// * `detections` - Detection results used to determine which techniques
    ///   are active and which are superseded.
    ///
    /// # Returns
    ///
    /// An ordered vec of technique references ready for sequential execution.
    #[must_use]
    pub fn sorted_techniques(&self, detections: &Detections) -> Vec<&dyn Technique> {
        // Computed per call: a few dozen techniques sort in microseconds, and a cache keyed
        // by the detections' generation answered one run with another's order, since every
        // run's detections count generations from zero on a registry the runs share.
        self.compute_sorted_indices(detections)
            .iter()
            .filter_map(|&i| self.techniques.get(i).map(|t| &**t))
            .collect()
    }

    /// Computes sorted technique indices via topological sort (Kahn's algorithm).
    ///
    /// Returns indices into `self.techniques` in dependency order, excluding
    /// techniques superseded by currently-detected techniques.
    fn compute_sorted_indices(&self, detections: &Detections) -> Vec<usize> {
        // 1. Build superseded set
        let mut superseded: HashSet<&str> = HashSet::new();
        for tech in &self.techniques {
            if detections.is_detected(tech.id()) {
                for s in tech.supersedes() {
                    superseded.insert(s);
                }
            }
        }

        // 2. Filter to eligible techniques (track original indices)
        let eligible: Vec<(usize, &dyn Technique)> = self
            .techniques
            .iter()
            .enumerate()
            .filter(|(_, t)| !superseded.contains(t.id()))
            .map(|(i, t)| (i, &**t))
            .collect();

        // 3. Build adjacency: map technique ID -> index in eligible list
        let id_to_idx: HashMap<&str, usize> = eligible
            .iter()
            .enumerate()
            .map(|(i, (_, t))| (t.id(), i))
            .collect();
        let n = eligible.len();

        // 4. Build in-degree counts and adjacency lists
        let mut in_degree = vec![0usize; n];
        let mut dependents: Vec<Vec<usize>> = vec![Vec::new(); n];

        for (idx, (_, tech)) in eligible.iter().enumerate() {
            for &req_id in tech.requires() {
                if let Some(&req_idx) = id_to_idx.get(req_id) {
                    // req_idx -> idx (req must come before this technique)
                    if let Some(deps) = dependents.get_mut(req_idx) {
                        deps.push(idx);
                    }
                    if let Some(d) = in_degree.get_mut(idx) {
                        *d = d.saturating_add(1);
                    }
                }
                // Missing dependency -> treat as satisfied (may be from a different phase)
            }
        }

        // 5. Kahn's algorithm: BFS from techniques with 0 in-degree
        let mut queue: VecDeque<usize> = VecDeque::new();
        for (idx, &deg) in in_degree.iter().enumerate() {
            if deg == 0 {
                queue.push_back(idx);
            }
        }

        let mut sorted: Vec<usize> = Vec::with_capacity(n);
        while let Some(idx) = queue.pop_front() {
            if let Some((orig_idx, _)) = eligible.get(idx) {
                sorted.push(*orig_idx);
            }
            let deps_for_idx: Vec<usize> = dependents.get(idx).cloned().unwrap_or_default();
            for dep_idx in deps_for_idx {
                if let Some(d) = in_degree.get_mut(dep_idx) {
                    *d = d.saturating_sub(1);
                    if *d == 0 {
                        queue.push_back(dep_idx);
                    }
                }
            }
        }

        // 6. Handle cycles: if remaining > 0, log warning and append
        if sorted.len() < n {
            log::warn!(
                "Technique dependency cycle detected: {} techniques could not be topologically sorted",
                n.saturating_sub(sorted.len())
            );
            let sorted_set: HashSet<usize> = sorted.iter().copied().collect();
            for &(orig_idx, _) in &eligible {
                if !sorted_set.contains(&orig_idx) {
                    sorted.push(orig_idx);
                }
            }
        }

        sorted
    }
}

impl Default for TechniqueRegistry {
    fn default() -> Self {
        Self::with_defaults()
    }
}

/// Matches technique detections to known obfuscator signatures.
///
/// Separated from [`TechniqueRegistry`] to decouple attribution logic
/// from technique storage and lifecycle management.
pub struct ObfuscatorMatcher {
    signatures: Vec<ObfuscatorSignature>,
}

impl ObfuscatorMatcher {
    /// Creates an empty matcher.
    #[must_use]
    pub fn new() -> Self {
        Self {
            signatures: Vec::new(),
        }
    }

    /// Creates a matcher with all built-in obfuscator signatures.
    #[must_use]
    pub fn with_defaults() -> Self {
        let mut matcher = Self::new();

        // ConfuserEx: definitive signal is the marker attribute it stamps on every
        // protected assembly. All other techniques add supporting evidence.
        matcher.add_signature(ObfuscatorSignature {
            name: "ConfuserEx",
            required: vec!["confuserex.marker"],
            supporting: vec![
                "confuserex.constants",
                "confuserex.proxy",
                "confuserex.debug",
                "confuserex.dump",
                "confuserex.tamper",
                "confuserex.resources",
                "confuserex.metadata",
                "confuserex.natives",
            ],
        });

        // BitMono: space-containing names (FullRenamer) combined with the br.s
        // junk prefix (BitMethodDotnet) are together highly specific to BitMono.
        matcher.add_signature(ObfuscatorSignature {
            name: "BitMono",
            required: vec!["bitmono.renamer", "bitmono.junk"],
            supporting: vec![
                "bitmono.strings",
                "bitmono.calli",
                "bitmono.debug",
                "bitmono.hooks",
                "bitmono.nops",
                "bitmono.unmanaged",
                "bitmono.pe",
                "bitmono.locals",
            ],
        });

        // BitMono single-technique signatures: each individual technique is
        // specific enough to BitMono's protection suite that detecting any one
        // of them is sufficient for attribution.
        let bitmono_ids: &[&str] = &[
            "bitmono.strings",
            "bitmono.calli",
            "bitmono.hooks",
            "bitmono.unmanaged",
            "bitmono.debug",
            "bitmono.junk",
            "bitmono.nops",
            "bitmono.pe",
            "bitmono.locals",
        ];
        for sig in single_technique_signatures("BitMono", bitmono_ids, &[]) {
            matcher.add_signature(sig);
        }

        // JIEJIE.NET: any single technique is sufficient for attribution.
        // Each technique's structural pattern is specific enough to JIEJIE.NET
        // that detecting one is a reliable signal. generic.flattening is a
        // common co-occurrence.
        let jiejie_ids: &[&str] = &[
            "jiejienet.constants",
            "jiejienet.strings",
            "jiejienet.typeof",
            "jiejienet.arrays",
            "jiejienet.resources",
        ];
        for sig in single_technique_signatures("JIEJIE.NET", jiejie_ids, &["generic.flattening"]) {
            matcher.add_signature(sig);
        }

        // Obfuscar: custom string decryption scheme is the primary identifier.
        matcher.add_signature(ObfuscatorSignature {
            name: "Obfuscar",
            required: vec!["obfuscar.strings"],
            supporting: vec![],
        });

        // .NET Reactor: any single NR-specific technique is sufficient for
        // attribution. NecroBit is the most distinctive (only NR encrypts
        // every method body via a `<Module>::.cctor` chain), but the other
        // NR techniques each match structural patterns that no other
        // obfuscator in the registry produces — `<PrivateImplementationDetails>{GUID}`
        // containers, the GUID-marker anti-tamper init runtime, the
        // `<Module>` trial-guard triplet, etc. Without this, samples
        // protected by NR but without NecroBit (e.g. `reactor_strings`,
        // `reactor_resources`, `reactor_antitamp`, `reactor_obfuscation`)
        // either get no attribution at all or get mis-attributed as
        // BitMono via single-technique BitMono signatures (`bitmono.junk`
        // false-positives on NR `br.s +5` anti-disassembly stubs).
        let netreactor_ids: &[&str] = &[
            "netreactor.necrobit",
            "netreactor.antitrial",
            "netreactor.antitamp",
            "netreactor.licensecheck",
            "netreactor.privateimpl",
            "netreactor.resources",
        ];
        for sig in single_technique_signatures(".NET Reactor", netreactor_ids, &[]) {
            matcher.add_signature(sig);
        }

        matcher
    }

    /// Adds an obfuscator signature.
    pub fn add_signature(&mut self, sig: ObfuscatorSignature) {
        self.signatures.push(sig);
    }

    /// Computes the best obfuscator attribution from technique detections.
    ///
    /// For each registered [`ObfuscatorSignature`], checks whether all
    /// `required` techniques are detected. Fully matched signatures are
    /// collected and sorted by the number of `supporting` techniques also
    /// detected (descending). The best match is returned.
    ///
    /// Returns `None` if no signature's required techniques are all detected.
    #[must_use]
    pub fn compute_attribution(&self, detections: &Detections) -> Option<AttributionResult> {
        let mut candidates: Vec<AttributionResult> = self
            .signatures
            .iter()
            .filter(|sig| sig.required.iter().all(|id| detections.is_detected(id)))
            .map(|sig| {
                let supporting_matched = sig
                    .supporting
                    .iter()
                    .filter(|id| detections.is_detected(id))
                    .count();

                let mut technique_ids: Vec<String> =
                    sig.required.iter().map(|s| s.to_string()).collect();
                for id in &sig.supporting {
                    if detections.is_detected(id) {
                        technique_ids.push(id.to_string());
                    }
                }

                AttributionResult {
                    obfuscator_name: sig.name.to_string(),
                    technique_ids,
                    supporting_matched,
                }
            })
            .collect();

        // Sort: most supporting matches first; break ties by required count (more = stronger).
        candidates.sort_by_key(|c| std::cmp::Reverse(c.supporting_matched));
        candidates.into_iter().next()
    }

    /// Returns attribution results for all detected obfuscators.
    ///
    /// Unlike [`Self::compute_attribution`] which returns only the single best match,
    /// this method returns one entry per unique obfuscator name — the best
    /// matching signature for each name — sorted by `supporting_matched`
    /// descending (most evidence first).
    #[must_use]
    pub fn compute_attributions_all(&self, detections: &Detections) -> Vec<AttributionResult> {
        let mut best_by_name: HashMap<&str, AttributionResult> = HashMap::new();

        for sig in &self.signatures {
            if !sig.required.iter().all(|id| detections.is_detected(id)) {
                continue;
            }

            let supporting_matched = sig
                .supporting
                .iter()
                .filter(|id| detections.is_detected(id))
                .count();

            let mut technique_ids: Vec<String> =
                sig.required.iter().map(|s| s.to_string()).collect();
            for id in &sig.supporting {
                if detections.is_detected(id) {
                    technique_ids.push(id.to_string());
                }
            }

            let candidate = AttributionResult {
                obfuscator_name: sig.name.to_string(),
                technique_ids,
                supporting_matched,
            };

            // Keep the best match (most supporting) per obfuscator name.
            match best_by_name.get(sig.name) {
                Some(existing) if existing.supporting_matched >= supporting_matched => {}
                _ => {
                    best_by_name.insert(sig.name, candidate);
                }
            }
        }

        let mut result: Vec<AttributionResult> = best_by_name.into_values().collect();
        result.sort_by_key(|r| std::cmp::Reverse(r.supporting_matched));
        result
    }
}

impl Default for ObfuscatorMatcher {
    fn default() -> Self {
        Self::with_defaults()
    }
}

/// Generates single-technique obfuscator signatures for a set of technique IDs.
///
/// For each ID in `all_ids`, creates a signature where that ID is the sole
/// required technique and all other IDs (plus `extra_supporting`) are supporting.
/// This pattern is used when each individual technique is specific enough for
/// attribution on its own.
fn single_technique_signatures(
    name: &'static str,
    all_ids: &[&'static str],
    extra_supporting: &[&'static str],
) -> Vec<ObfuscatorSignature> {
    all_ids
        .iter()
        .map(|&required_id| {
            let mut supporting: Vec<&'static str> = all_ids
                .iter()
                .filter(|&&id| id != required_id)
                .copied()
                .collect();
            supporting.extend_from_slice(extra_supporting);
            ObfuscatorSignature {
                name,
                required: vec![required_id],
                supporting,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::{
        deobfuscation::techniques::{
            Detection, Detections, ObfuscatorMatcher, ObfuscatorSignature, Technique,
            TechniqueCapability, TechniqueCategory, TechniqueRegistry, WorkingAssembly,
        },
        testkit::helpers::load_sample,
    };

    #[test]
    fn a_technique_declares_byte_transform_exactly_when_it_has_one() {
        // Cleanup withholds what a failed or never-run byte transform's technique would remove,
        // and the pipeline reruns for a pending one, both by the declared capability; the
        // declaration must be the transform's. Every byte transform answers an empty detection,
        // with an empty event log; a technique without one answers nothing.
        let registry = TechniqueRegistry::with_defaults();
        for technique in registry.techniques() {
            let mut assembly =
                WorkingAssembly::new(load_sample("packers/confuserex/1.6.0/original.exe"));
            let has_transform = technique
                .byte_transform(&mut assembly, &mut Detection::new_empty())
                .is_some();
            let declares = technique
                .capabilities()
                .contains(&TechniqueCapability::ByteTransform);
            assert_eq!(has_transform, declares, "{}", technique.id());
        }
    }

    /// Minimal mock technique for registry tests.
    struct MockTechnique {
        id: &'static str,
        requires: &'static [&'static str],
        supersedes: &'static [&'static str],
    }

    impl MockTechnique {
        fn new(id: &'static str) -> Self {
            Self {
                id,
                requires: &[],
                supersedes: &[],
            }
        }

        fn with_requires(id: &'static str, requires: &'static [&'static str]) -> Self {
            Self {
                id,
                requires,
                supersedes: &[],
            }
        }

        fn with_supersedes(id: &'static str, supersedes: &'static [&'static str]) -> Self {
            Self {
                id,
                requires: &[],
                supersedes,
            }
        }
    }

    impl Technique for MockTechnique {
        fn id(&self) -> &'static str {
            self.id
        }
        fn name(&self) -> &'static str {
            self.id
        }
        fn category(&self) -> TechniqueCategory {
            TechniqueCategory::Metadata
        }
        fn detect(&self, _assembly: &crate::CilObject) -> Detection {
            Detection::new_empty()
        }
        fn requires(&self) -> &[&'static str] {
            self.requires
        }
        fn supersedes(&self) -> &[&'static str] {
            self.supersedes
        }
    }

    // TechniqueRegistry tests

    #[test]
    fn test_registry_new_is_empty() {
        let r = TechniqueRegistry::new();
        assert!(!r.has_techniques());
        assert!(r.techniques().is_empty());
    }

    #[test]
    fn test_registry_register_and_retrieve() {
        let mut r = TechniqueRegistry::new();
        r.register(Box::new(MockTechnique::new("test.a")));
        r.register(Box::new(MockTechnique::new("test.b")));

        assert!(r.has_techniques());
        assert_eq!(r.techniques().len(), 2);
        assert_eq!(r.techniques()[0].id(), "test.a");
        assert_eq!(r.techniques()[1].id(), "test.b");
    }

    #[test]
    fn test_with_defaults_has_techniques() {
        let r = TechniqueRegistry::with_defaults();
        assert!(r.has_techniques());
        assert!(r.techniques().len() >= 30);
    }

    #[test]
    fn test_sorted_techniques_dependency_order() {
        let mut r = TechniqueRegistry::new();
        r.register(Box::new(MockTechnique::with_requires("b", &["a"])));
        r.register(Box::new(MockTechnique::new("a")));

        let ds = Detections::new();
        let sorted = r.sorted_techniques(&ds);
        let ids: Vec<&str> = sorted.iter().map(|t| t.id()).collect();
        // "a" has 0 requires, "b" has 1 — so "a" comes first
        assert_eq!(ids, vec!["a", "b"]);
    }

    #[test]
    fn test_sorted_techniques_topological_diamond() {
        // Diamond: A -> B, A -> C, B -> D, C -> D
        let mut r = TechniqueRegistry::new();
        r.register(Box::new(MockTechnique::with_requires("d", &["b", "c"])));
        r.register(Box::new(MockTechnique::with_requires("b", &["a"])));
        r.register(Box::new(MockTechnique::with_requires("c", &["a"])));
        r.register(Box::new(MockTechnique::new("a")));

        let ds = Detections::new();
        let sorted = r.sorted_techniques(&ds);
        let ids: Vec<&str> = sorted.iter().map(|t| t.id()).collect();

        // "a" must come before "b" and "c", both must come before "d"
        let pos = |id: &str| ids.iter().position(|&x| x == id).unwrap();
        assert!(pos("a") < pos("b"));
        assert!(pos("a") < pos("c"));
        assert!(pos("b") < pos("d"));
        assert!(pos("c") < pos("d"));
    }

    #[test]
    fn test_sorted_techniques_missing_dependency() {
        // "b" requires "nonexistent" — should still be included
        let mut r = TechniqueRegistry::new();
        r.register(Box::new(MockTechnique::new("a")));
        r.register(Box::new(MockTechnique::with_requires(
            "b",
            &["nonexistent"],
        )));

        let ds = Detections::new();
        let sorted = r.sorted_techniques(&ds);
        let ids: Vec<&str> = sorted.iter().map(|t| t.id()).collect();
        assert!(ids.contains(&"a"));
        assert!(ids.contains(&"b"));
    }

    #[test]
    fn test_sorted_techniques_supersedes_filtering() {
        let mut r = TechniqueRegistry::new();
        r.register(Box::new(MockTechnique::new("old")));
        r.register(Box::new(MockTechnique::with_supersedes("new", &["old"])));

        let mut ds = Detections::new();
        ds.insert("new", Detection::new_detected(vec![], None));

        let sorted = r.sorted_techniques(&ds);
        let ids: Vec<&str> = sorted.iter().map(|t| t.id()).collect();
        // "old" should be excluded because "new" supersedes it and is detected
        assert!(!ids.contains(&"old"));
        assert!(ids.contains(&"new"));
    }

    /// Two runs on one registry each count their detections' generations from zero: the
    /// order one run's detections give is not the other's. A cache keyed by the generation
    /// alone answered the second run with the first's, leaving out a technique only the first
    /// run had superseded.
    #[test]
    fn runs_sharing_a_registry_get_their_own_order() {
        let mut r = TechniqueRegistry::new();
        r.register(Box::new(MockTechnique::new("old")));
        r.register(Box::new(MockTechnique::with_supersedes("new", &["old"])));

        // One insert each: the same generation
        let mut first = Detections::new();
        first.insert("new", Detection::new_detected(vec![], None));
        let mut second = Detections::new();
        second.insert("old", Detection::new_detected(vec![], None));
        assert_eq!(first.generation(), second.generation());

        let first_ids: Vec<&str> = r.sorted_techniques(&first).iter().map(|t| t.id()).collect();
        let second_ids: Vec<&str> = r
            .sorted_techniques(&second)
            .iter()
            .map(|t| t.id())
            .collect();
        assert!(!first_ids.contains(&"old"), "superseded in the first run");
        assert!(
            second_ids.contains(&"old"),
            "nothing supersedes it in the second"
        );
    }

    #[test]
    fn test_sorted_techniques_supersedes_not_detected() {
        let mut r = TechniqueRegistry::new();
        r.register(Box::new(MockTechnique::new("old")));
        r.register(Box::new(MockTechnique::with_supersedes("new", &["old"])));

        let ds = Detections::new(); // nothing detected
        let sorted = r.sorted_techniques(&ds);
        let ids: Vec<&str> = sorted.iter().map(|t| t.id()).collect();
        // Both should be present since "new" is not detected
        assert!(ids.contains(&"old"));
        assert!(ids.contains(&"new"));
    }

    #[test]
    fn test_registry_default() {
        let r = TechniqueRegistry::default();
        assert!(r.has_techniques());
        assert!(r.techniques().len() >= 30);
    }

    // ObfuscatorMatcher tests

    #[test]
    fn test_compute_attribution_no_match() {
        let mut m = ObfuscatorMatcher::new();
        m.add_signature(ObfuscatorSignature {
            name: "TestObfuscator",
            required: vec!["test.a"],
            supporting: vec![],
        });

        let ds = Detections::new();
        assert!(m.compute_attribution(&ds).is_none());
    }

    #[test]
    fn test_compute_attribution_required_match() {
        let mut m = ObfuscatorMatcher::new();
        m.add_signature(ObfuscatorSignature {
            name: "TestObfuscator",
            required: vec!["test.a"],
            supporting: vec!["test.b"],
        });

        let mut ds = Detections::new();
        ds.insert("test.a", Detection::new_detected(vec![], None));

        let attr = m.compute_attribution(&ds).unwrap();
        assert_eq!(attr.obfuscator_name, "TestObfuscator");
        assert_eq!(attr.supporting_matched, 0);
    }

    #[test]
    fn test_compute_attribution_with_supporting() {
        let mut m = ObfuscatorMatcher::new();
        m.add_signature(ObfuscatorSignature {
            name: "TestObfuscator",
            required: vec!["test.a"],
            supporting: vec!["test.b", "test.c"],
        });

        let mut ds = Detections::new();
        ds.insert("test.a", Detection::new_detected(vec![], None));
        ds.insert("test.b", Detection::new_detected(vec![], None));

        let attr = m.compute_attribution(&ds).unwrap();
        assert_eq!(attr.supporting_matched, 1);
        assert!(attr.technique_ids.contains(&"test.a".to_string()));
        assert!(attr.technique_ids.contains(&"test.b".to_string()));
    }

    #[test]
    fn test_compute_attribution_best_match_wins() {
        let mut m = ObfuscatorMatcher::new();
        m.add_signature(ObfuscatorSignature {
            name: "Weak",
            required: vec!["weak.a"],
            supporting: vec![],
        });
        m.add_signature(ObfuscatorSignature {
            name: "Strong",
            required: vec!["strong.a"],
            supporting: vec!["strong.b", "strong.c"],
        });

        let mut ds = Detections::new();
        ds.insert("weak.a", Detection::new_detected(vec![], None));
        ds.insert("strong.a", Detection::new_detected(vec![], None));
        ds.insert("strong.b", Detection::new_detected(vec![], None));
        ds.insert("strong.c", Detection::new_detected(vec![], None));

        let attr = m.compute_attribution(&ds).unwrap();
        assert_eq!(attr.obfuscator_name, "Strong");
        assert_eq!(attr.supporting_matched, 2);
    }

    #[test]
    fn test_compute_attributions_all() {
        let mut m = ObfuscatorMatcher::new();
        m.add_signature(ObfuscatorSignature {
            name: "Alpha",
            required: vec!["alpha.a"],
            supporting: vec![],
        });
        m.add_signature(ObfuscatorSignature {
            name: "Beta",
            required: vec!["beta.a"],
            supporting: vec!["beta.b"],
        });

        let mut ds = Detections::new();
        ds.insert("alpha.a", Detection::new_detected(vec![], None));
        ds.insert("beta.a", Detection::new_detected(vec![], None));
        ds.insert("beta.b", Detection::new_detected(vec![], None));

        let attrs = m.compute_attributions_all(&ds);
        assert_eq!(attrs.len(), 2);
        // Beta has more supporting matches, should come first
        assert_eq!(attrs[0].obfuscator_name, "Beta");
        assert_eq!(attrs[1].obfuscator_name, "Alpha");
    }

    #[test]
    fn test_matcher_default() {
        let m = ObfuscatorMatcher::default();
        assert!(m.compute_attribution(&Detections::new()).is_none());
    }

    #[test]
    fn test_matcher_with_defaults_has_signatures() {
        let m = ObfuscatorMatcher::with_defaults();

        // Verify ConfuserEx attribution works
        let mut ds = Detections::new();
        ds.insert("confuserex.marker", Detection::new_detected(vec![], None));
        let attr = m.compute_attribution(&ds).unwrap();
        assert_eq!(attr.obfuscator_name, "ConfuserEx");

        // Verify BitMono attribution works (single technique)
        let mut ds = Detections::new();
        ds.insert("bitmono.strings", Detection::new_detected(vec![], None));
        let attr = m.compute_attribution(&ds).unwrap();
        assert_eq!(attr.obfuscator_name, "BitMono");

        // Verify JIEJIE.NET attribution works (single technique)
        let mut ds = Detections::new();
        ds.insert("jiejienet.constants", Detection::new_detected(vec![], None));
        let attr = m.compute_attribution(&ds).unwrap();
        assert_eq!(attr.obfuscator_name, "JIEJIE.NET");

        // Verify .NET Reactor attribution works from ANY single NR technique,
        // not only NecroBit. NR samples without NecroBit (e.g. strings-only,
        // resources-only) must still attribute as ".NET Reactor".
        for nr_id in &[
            "netreactor.necrobit",
            "netreactor.antitrial",
            "netreactor.antitamp",
            "netreactor.licensecheck",
            "netreactor.privateimpl",
            "netreactor.resources",
        ] {
            let mut ds = Detections::new();
            ds.insert(*nr_id, Detection::new_detected(vec![], None));
            let attr = m.compute_attribution(&ds).unwrap_or_else(|| {
                panic!("Single NR technique {nr_id} should attribute to .NET Reactor")
            });
            assert_eq!(
                attr.obfuscator_name, ".NET Reactor",
                "{nr_id} should attribute to .NET Reactor"
            );
        }
    }
}
