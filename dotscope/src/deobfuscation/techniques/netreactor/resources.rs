//! .NET Reactor resource encryption removal.
//!
//! NR's resource-encryption stage merges every manifest resource into one
//! AES-encrypted blob, deletes the originals, and injects a runtime resolver
//! type that re-publishes the decrypted resources via an
//! [`AppDomain.ResourceResolve`] handler. The resolver's decryption method
//! (`OpMPoypqBX` in research notation) is a CFF dispatcher with ~1000 switch
//! cases that mono cannot run reliably — `reactor_resources.exe` hangs mid-run
//! when the first `GetManifestResourceStream` call triggers the handler.
//!
//! This technique:
//!
//! 1. Detects the resolver type structurally (lazy-init shape + handler
//!    registration + massive CFF dispatcher + named encrypted resource).
//! 2. Emulates the handler against the protected assembly to recover the
//!    decrypted resource bytes (reuses the same `EmulationProcess`
//!    infrastructure as `netreactor.necrobit`).
//! 3. Inserts each decrypted resource as a real `ManifestResource` row in the
//!    output assembly, restoring the original layout.
//! 4. Marks the resolver type, lazy-init injection sites, and the encrypted
//!    blob for cleanup.
//!
//! # Pipeline
//!
//! 1. **Detection** ([`detect`](Technique::detect)) — locates the
//!    resolver type, its lazy-init / `.ctor` / dispatcher / handler /
//!    reflective `Assembly.Load` shims, every `lazy_init` injection
//!    site, the encrypted resource(s), and the BCL MemberRef for
//!    `Assembly::GetManifestResourceNames`. Marks the resolver type,
//!    the encrypted blob, and the purely-injected `.cctor`s for cleanup.
//! 2. **`byte_transform`** ([`byte_transform`](Technique::byte_transform))
//!    — drives the dispatcher once under emulation. The reflective
//!    `Assembly.Load(byte[])` shim is intercepted by
//!    [`hooks::create_resources_load_shim_hook`]
//!    so the decrypted bytes land in `CaptureContext`. The captured
//!    PE is parsed and its embedded resources are re-injected as real
//!    `ManifestResource` rows.
//! 3. **SSA rewrite** ([`create_pass`](Technique::create_pass)) —
//!    [`ResourceShimRewritePass`] retargets every user-code shim
//!    `Call(eBxqprrF8, [asm])` to a `callvirt(GetManifestResourceNames,
//!    [asm])`, and turns every `Call(lazy_init)` into `Nop`. After the
//!    pass runs no surviving user code references the resolver type.
//! 4. **Cleanup** — the marked resolver type, encrypted blob, and
//!    purely-injected `.cctor`s are removed by the generic cleanup
//!    pipeline (the `protect_token` machinery in
//!    `build_cleanup_request` keeps them alive only if any unresolved
//!    failure remains, which never happens once the rewrite pass
//!    fires).
//!
//! # Verified
//!
//! On `reactor_resources.exe`:
//!
//! - 2,048-byte deflated payload decompresses end-to-end (depended on
//!   the `Stream.CopyTo` fix in `runtime/bcl/io/stream.rs` for
//!   `DeflateStream` / `CryptoStream` sources).
//! - All three original resources are recovered with correct sizes
//!   (`greeting.txt` 163 B, `data.bin` 24 B, `TestApp.g.resources`
//!   180 B).
//! - The `eBxqprrF8` shim call in `DemoEmbeddedResources` is rewritten
//!   to `Assembly::GetManifestResourceNames`; both `Main` and
//!   `Program::.cctor` lazy-init calls are NOPed.
//! - Resolver type, encrypted blob, and injected `.cctor` all
//!   disappear from the deobfuscated output; mono runs the recovered
//!   binary cleanly.
//!
//! # Detection signals (all structural — no name/version dependence)
//!
//! 1. A `static void` lazy-init method with the shape
//!    `ldsfld <bool>; brtrue; ldc.i4.1; stsfld <same bool>; newobj T; pop; ret`.
//! 2. The instance constructor of `T` registers a handler via
//!    `AppDomain::add_ResourceResolve` (or `add_AssemblyResolve`) using a
//!    `ldftn` to a same-type method whose signature is
//!    `(object, X) -> Assembly`.
//! 3. `T` owns at least one method with a `switch` instruction having ≥ 200
//!    case entries (the CFF-flattened decryption engine).
//! 4. `T` (or a nested type) loads a manifest resource by name via
//!    `ldstr <name>` matching an entry in the assembly's resources table.
//!
//! All four signals must hold to accept the candidate.
//!
//! [`AppDomain.ResourceResolve`]: https://learn.microsoft.com/dotnet/api/system.appdomain.resourceresolve

use std::{any::Any, collections::HashSet, sync::Arc};

use crate::{
    analysis::CilTarget,
    assembly::Operand,
    cilassembly::GeneratorConfig,
    compiler::{CompilerContext, EventKind, EventLog, PassPhase, SsaPass},
    deobfuscation::{
        context::AnalysisContext,
        passes::netreactor::ResourceShimRewritePass,
        techniques::{
            netreactor::{
                helpers::{self, find_resources_referenced_by_methods},
                hooks,
            },
            Detection, Evidence, Technique, TechniqueCapability, TechniqueCategory,
            WorkingAssembly,
        },
    },
    emulation::{tokens, CapturedAssembly, EmValue, EmulationOutcome, ProcessBuilder},
    error::Error,
    metadata::{
        method::MethodRc,
        signatures::TypeSignature,
        tables::ManifestResourceBuilder,
        token::Token,
        typesystem::{wellknown, CilTypeRc, CilTypeReference},
        validation::ValidationConfig,
    },
    CilObject, Result,
};

/// Minimum switch-case count for the CFF dispatcher signal.
///
/// The smallest observed dispatcher (`reactor_resources`) has ~1185 cases;
/// guarding at 200 stays well clear of any plausible legitimate switch.
const MIN_DISPATCHER_CASES: usize = 200;

/// Findings from .NET Reactor resource-encryption detection.
#[derive(Debug)]
pub struct ResourceFindings {
    /// TypeDef token of the resource resolver type.
    pub resolver_type_token: Token,
    /// Token of the lazy-init method (`static void X()`).
    pub lazy_init_token: Token,
    /// Token of the resolver type's instance `.ctor` (registers the handler).
    pub resolver_ctor_token: Token,
    /// Token of the resource-resolve handler method
    /// (`static Assembly handler(object, X)`).
    pub handler_method_token: Token,
    /// Token of the CFF-flattened decryption engine (`OpMPoypqBX`-shape).
    pub decrypter_method_token: Token,
    /// `ManifestResource` tokens referenced by name from resolver-owned
    /// methods. These are the encrypted blobs the runtime decrypts. Empty when
    /// the names are themselves encrypted, as .NET Reactor's string encryption
    /// makes them; the transform then learns the blobs from what the
    /// resolver's methods open while its decrypter runs.
    pub encrypted_resource_tokens: Vec<Token>,
    /// Methods whose first IL instruction is `call lazy_init`. Used by the
    /// IL rewrite pass to NOP the injected init call. Includes Main + any
    /// type `.cctor` the protector touched.
    pub lazy_init_call_sites: Vec<Token>,
    /// Tokens of injected `.cctor`s whose entire body is
    /// `call lazy_init; ret`. Safe to delete outright (matches the
    /// `helpers::classify_injected_cctors` shape used elsewhere).
    pub purely_injected_cctors: Vec<Token>,
    /// Tokens of methods on the resolver type (or its nested types) that
    /// reflectively invoke `Assembly.Load(byte[])`. Hooked during emulation
    /// so the decrypter's byte-array argument is captured even though our
    /// `Type.GetMethod` BCL stub can't resolve `Assembly::Load` natively.
    pub assembly_load_shim_tokens: Vec<Token>,
    /// Tokens of `static (Assembly) -> string[]` shim methods on the
    /// resolver type that wrap `Assembly::GetManifestResourceNames()`.
    /// User code calls these instead of the BCL method directly; the SSA
    /// rewrite pass retargets each call to the BCL MemberRef so the
    /// resolver type can be deleted.
    pub get_manifest_resource_names_shim_tokens: Vec<Token>,
    /// MemberRef token for
    /// `[mscorlib]System.Reflection.Assembly::GetManifestResourceNames()`,
    /// resolved from the assembly's import table at detection time. The
    /// SSA rewrite pass uses it as the replacement target for every
    /// shim call. `Token::new(0)` when not found, in which case the
    /// rewrite pass leaves shim calls intact.
    pub bcl_get_manifest_resource_names: Token,
}

/// Detects and removes .NET Reactor's resource-encryption stage.
pub struct NetReactorResources;

impl Technique for NetReactorResources {
    fn id(&self) -> &'static str {
        "netreactor.resources"
    }

    fn name(&self) -> &'static str {
        ".NET Reactor Resource Decryption"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Value
    }

    fn capabilities(&self) -> Vec<TechniqueCapability> {
        vec![
            TechniqueCapability::ByteTransform,
            TechniqueCapability::SsaPass,
        ]
    }

    fn detect(&self, assembly: &CilObject) -> Detection {
        let Some(candidate) = find_resolver_candidate(assembly) else {
            return Detection::new_empty();
        };

        let runtime_method_tokens: Vec<Token> =
            candidate.resolver_type.methods().map(|m| m.token).collect();
        // The blob the runtime decrypts, when its name is in the clear. With
        // string encryption on it is not, and the transform finds the blob by
        // watching the decrypter open it instead.
        let encrypted_resource_tokens =
            find_resources_referenced_by_methods(assembly, &runtime_method_tokens);

        let lazy_init_call_sites = find_lazy_init_call_sites(assembly, candidate.lazy_init_token);
        let purely_injected_cctors =
            classify_purely_injected_cctors(assembly, candidate.lazy_init_token);
        // Anti-tamper replaces each `ldtoken` with a raw token passed to its
        // metadata-token resolver; the shims then name the type that way.
        let type_handle_accessors = helpers::find_nr_token_resolver(assembly)
            .map(|resolver| resolver.type_handle_accessors)
            .unwrap_or_default();
        let assembly_load_shim_tokens = find_assembly_load_shim_methods(
            assembly,
            &candidate.resolver_type,
            &type_handle_accessors,
        );
        let get_manifest_resource_names_shim_tokens =
            find_get_manifest_resource_names_shims(assembly, &candidate.resolver_type);
        let bcl_get_manifest_resource_names = find_bcl_member_ref(
            assembly,
            "System.Reflection.Assembly",
            "GetManifestResourceNames",
        )
        .unwrap_or_else(|| Token::new(0));

        let evidence = vec![
            Evidence::Structural(format!(
                "Resolver type 0x{:08X} with handler 0x{:08X} + dispatcher 0x{:08X} \
                 ({} switch cases)",
                candidate.resolver_type.token.value(),
                candidate.handler_method_token.value(),
                candidate.decrypter_method_token.value(),
                candidate.dispatcher_case_count,
            )),
            Evidence::Structural(format!(
                "Lazy init 0x{:08X} called from {} site(s); {} purely-injected .cctor(s); \
                 {} encrypted resource(s); {} Assembly.Load reflection shim(s); \
                 {} GetManifestResourceNames shim(s); \
                 BCL GetManifestResourceNames MemberRef = 0x{:08X}",
                candidate.lazy_init_token.value(),
                lazy_init_call_sites.len(),
                purely_injected_cctors.len(),
                encrypted_resource_tokens.len(),
                assembly_load_shim_tokens.len(),
                get_manifest_resource_names_shim_tokens.len(),
                bcl_get_manifest_resource_names.value(),
            )),
        ];

        let findings = ResourceFindings {
            resolver_type_token: candidate.resolver_type.token,
            lazy_init_token: candidate.lazy_init_token,
            resolver_ctor_token: candidate.resolver_ctor_token,
            handler_method_token: candidate.handler_method_token,
            decrypter_method_token: candidate.decrypter_method_token,
            encrypted_resource_tokens: encrypted_resource_tokens.clone(),
            lazy_init_call_sites,
            purely_injected_cctors: purely_injected_cctors.clone(),
            assembly_load_shim_tokens,
            get_manifest_resource_names_shim_tokens,
            bcl_get_manifest_resource_names,
        };

        let mut detection = Detection::new_detected(
            evidence,
            Some(Box::new(findings) as Box<dyn Any + Send + Sync>),
        );

        // Mark the encrypted blob + the purely-injected `.cctor`s for
        // cleanup. The resolver type is left for the orphan sweep to
        // collect: marking it for explicit removal triggers
        // [`NeutralizationPass`] to NOP every call to its methods, but
        // the SSA rewrite has already retargeted those calls to BCL APIs
        // — running the neutraliser on top of the rewrite gutted the
        // calling user methods (every BCL call after the rewritten one
        // was treated as taint-reachable from the now-deleted shim and
        // wiped). Leaving the resolver type for orphan cleanup keeps the
        // user IL intact and still removes the type once nothing
        // references it post-rewrite.
        for &res in &encrypted_resource_tokens {
            detection.cleanup_mut().add_manifest_resource(res);
        }
        for &cctor in &purely_injected_cctors {
            detection.cleanup_mut().add_method(cctor);
        }

        detection
    }

    fn create_pass(
        &self,
        _ctx: &AnalysisContext,
        detection: &Detection,
        _assembly: &Arc<CilObject>,
    ) -> Vec<Box<dyn SsaPass<CilTarget, CompilerContext>>> {
        let Some(findings) = detection.findings::<ResourceFindings>() else {
            return Vec::new();
        };
        // Both rewrites must run together: NOPing only the lazy_init
        // calls would let `find_unreferenced_types` notice the resolver
        // type and add it to cleanup; the neutralisation pass would then
        // taint every call to its surviving methods (including the
        // GetManifestResourceNames shim call in `DemoEmbeddedResources`)
        // and gut the calling user methods. Rewriting the shim too
        // keeps user IL intact across the cleanup boundary.
        //
        // The `assembly_load_shim_tokens` here are the
        // `GetManifestResourceNames` wrappers that user code calls —
        // NOT the reflective `Assembly.Load` wrappers (those are
        // emulator-only and are intercepted by the runtime hook in
        // `byte_transform`).
        vec![Box::new(ResourceShimRewritePass::new(
            findings
                .get_manifest_resource_names_shim_tokens
                .iter()
                .copied(),
            findings.lazy_init_token,
            findings.bcl_get_manifest_resource_names,
        ))]
    }

    fn ssa_phase(&self) -> Option<PassPhase> {
        // Same phase as the other NR shim folders — runs alongside the
        // value-folding stage so the rewrites land before final cleanup.
        Some(PassPhase::Value)
    }

    fn byte_transform(
        &self,
        assembly: &mut WorkingAssembly,
        detection: &mut Detection,
    ) -> Option<Result<EventLog>> {
        let events = EventLog::new();
        let Some(findings) = detection.findings::<ResourceFindings>() else {
            return Some(Ok(events));
        };

        // Step 1: parse the working assembly's bytes ONCE. The same
        // `CilObject` is shared with the emulator (via `Arc`) and then
        // unwrapped for mutation once emulation completes — no second
        // round-trip parse.
        let co = match assembly.cilobject() {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };
        let bytes = co.file().data().to_vec();
        let cilobject =
            match CilObject::from_mem_with_validation(bytes, ValidationConfig::analysis()) {
                Ok(v) => v,
                Err(e) => return Some(Err(e)),
            };

        // Resolve the assembly-specific TypeRef token for
        // `[mscorlib]System.Reflection.Assembly` once, before wrapping in
        // `Arc` (the lookup is read-only).
        let assembly_typeref = match find_assembly_typeref(&cilobject) {
            Some(t) => t,
            None => {
                return Some(Err(Error::Deobfuscation(
                    "NR resources: assembly does not import \
                     System.Reflection.Assembly — cannot install Load shim hook"
                        .to_string(),
                )));
            }
        };

        let cilobject_arc = Arc::new(cilobject);

        // Step 2: build the emulation process. The dispatcher is large
        // (~1000+ switch cases) and runs through Deflate decompression +
        // a BinaryReader decode loop, so give it generous instruction +
        // call-depth limits.
        let shim_set: HashSet<Token> = findings.assembly_load_shim_tokens.iter().copied().collect();
        let mut builder = ProcessBuilder::new()
            .assembly_arc(Arc::clone(&cilobject_arc))
            .name("netreactor-resources")
            .with_max_instructions(50_000_000)
            .with_max_call_depth(200)
            .with_timeout_ms(120_000)
            // Capture is opt-in on `ProcessBuilder`; enable it explicitly
            // so the shim hook's `capture_assembly` calls actually persist.
            .capture_assemblies()
            // With anti-tamper on, the runtime the decrypter belongs to checks
            // the image's RSA signature first, and the image it runs in here
            // has already been rewritten by the transforms before this one:
            // the check fails with "<name> is tampered." and nothing is
            // decrypted. The same bypass NecroBit's emulation uses.
            .hook(hooks::create_antitamper_bypass_hook());
        // The trial checks compare `DateTime.Now` with the protection date, and the emulator
        // cannot know when that was: the decrypter would throw "protected by an unregistered
        // version" before decrypting anything. The same bypass NecroBit's emulation uses.
        let trial_checks: HashSet<Token> = helpers::find_trial_checks(&cilobject_arc)
            .into_iter()
            .map(|trial| trial.method_token)
            .collect();
        if !trial_checks.is_empty() {
            builder = builder.hook(hooks::create_trial_bypass_hook(trial_checks));
        }
        if !shim_set.is_empty() {
            builder = builder.hook(hooks::create_resources_load_shim_hook(
                shim_set,
                assembly_typeref,
            ));
        }
        let process = match builder.build() {
            Ok(p) => p,
            Err(e) => return Some(Err(e)),
        };

        // Step 3: drive the dispatcher. `OpMPoypqBX` is `static void` and
        // self-gates via a static `bool` — one call exercises the full
        // decrypt path and stores the resulting Assembly object via the
        // reflective `Assembly.Load(byte[])` shim, which our hook
        // captures.
        let outcome = match process.execute_method(findings.decrypter_method_token, vec![]) {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };
        let instructions_executed = match &outcome {
            EmulationOutcome::Completed { instructions, .. }
            | EmulationOutcome::Breakpoint { instructions, .. } => *instructions,
            EmulationOutcome::UnhandledException {
                instructions,
                exception,
                ..
            } => {
                // Name the exception's type; a heap reference alone says
                // nothing about why the decrypter stopped.
                let thrown = match exception {
                    EmValue::ObjectRef(href) => {
                        let heap = process.address_space().managed_heap();
                        let type_name = heap
                            .get_type_token(*href)
                            .ok()
                            .and_then(|token| cilobject_arc.types().get(&token))
                            .map_or_else(
                                || format!("{exception:?}"),
                                |ty| ty.fullname().to_string(),
                            );
                        let message = heap
                            .get_field(*href, tokens::exception_fields::MESSAGE)
                            .ok()
                            .and_then(|value| match value {
                                EmValue::ObjectRef(text) => heap.get_string(text).ok(),
                                _ => None,
                            });
                        match message {
                            Some(message) => format!("{type_name} (\"{message}\")"),
                            None => type_name,
                        }
                    }
                    other => format!("{other:?}"),
                };
                log::info!(
                    "NR resources: decrypter raised {thrown} after {instructions} instructions; \
                     extracting any captured assemblies"
                );
                *instructions
            }
            EmulationOutcome::LimitReached { limit, .. } => {
                log::warn!(
                    "NR resources: decrypter exceeded limit ({limit:?}) — \
                     attempting capture extraction from partial state"
                );
                0
            }
            EmulationOutcome::Stopped { reason, .. } => {
                return Some(Err(Error::Deobfuscation(format!(
                    "NR resources: decrypter stopped: {reason}"
                ))));
            }
            EmulationOutcome::RequiresSymbolic { reason, .. } => {
                return Some(Err(Error::Deobfuscation(format!(
                    "NR resources: decrypter requires symbolic execution: {reason}"
                ))));
            }
        };

        // Step 4: pull captured assemblies out of the process before
        // unwrapping so we don't have to keep `process` alive past the
        // `Arc::try_unwrap`.
        let captured = process.capture().assemblies();
        // The blobs are what the resolver's own methods opened. The decrypter
        // runs other protections' code on the way (the string decryptor opens
        // its own resource), and those resources are not this technique's.
        let resolver_methods: HashSet<Token> = cilobject_arc
            .types()
            .get(&findings.resolver_type_token)
            .map(|resolver| collect_type_methods(&resolver))
            .unwrap_or_default();
        let consumed: Vec<Token> = process
            .capture()
            .resource_reads()
            .into_iter()
            .filter(|read| {
                read.reader
                    .is_some_and(|reader| resolver_methods.contains(&reader))
            })
            .map(|read| read.resource)
            .collect();
        drop(process);

        if captured.is_empty() {
            log::debug!(
                "NR resources: decrypter completed ({instructions_executed} instructions) \
                 but no Assembly bytes were captured — leaving encrypted blob in place"
            );
            return Some(Ok(events));
        }

        log::info!(
            "NR resources: decrypter ran in {instructions_executed} instructions, \
             captured {} Assembly.Load(byte[]) call(s)",
            captured.len()
        );

        // Step 5: parse each captured assembly and harvest its embedded
        // resources. The decrypted assembly is a real .NET PE — resources
        // are flat `ManifestResource` rows with raw byte contents.
        let decrypted_resources = harvest_resources(&captured);
        if decrypted_resources.is_empty() {
            return Some(Err(Error::Deobfuscation(
                "NR resources: captured assemblies contained no extractable resources".to_string(),
            )));
        }
        log::info!(
            "NR resources: recovered {} embedded resource(s) from captured assemblies",
            decrypted_resources.len()
        );
        for (name, data) in &decrypted_resources {
            log::debug!("NR resources: recovered {:?} ({} bytes)", name, data.len());
        }

        // Step 6: unwrap the shared `CilObject` and convert to a
        // mutable `CilAssembly`. Reusing the `Arc` we built for emulation
        // avoids re-parsing the working assembly's bytes a second time.
        let cilobject = match Arc::try_unwrap(cilobject_arc).map_err(|_| {
            Error::Deobfuscation(
                "NR resources: emulation assembly still shared after process drop".to_string(),
            )
        }) {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };
        let mut cil_assembly = cilobject.into_assembly();

        let mut injected = 0usize;
        for (name, data) in &decrypted_resources {
            match ManifestResourceBuilder::new()
                .name(name.clone())
                .public()
                .resource_data(data)
                .build(&mut cil_assembly)
            {
                Ok(_) => {
                    injected = injected.saturating_add(1);
                    events.record(EventKind::ResourceDecrypted).message(format!(
                        "Injected NR-decrypted resource {:?} ({} bytes)",
                        name,
                        data.len()
                    ));
                }
                Err(e) => {
                    log::warn!(
                        "NR resources: failed to inject {:?} ({} bytes): {e}",
                        name,
                        data.len()
                    );
                }
            }
        }

        if injected == 0 {
            return Some(Err(Error::Deobfuscation(
                "NR resources: failed to inject any decrypted resource".to_string(),
            )));
        }

        events.record(EventKind::ResourceDecrypted).message(format!(
            "NR resources: {injected} resource(s) restored from {} captured assembly bytes \
             ({instructions_executed} instructions emulated)",
            captured.iter().map(|c| c.data.len()).sum::<usize>(),
        ));

        // Step 7: regenerate the PE so the new resources land in the
        // working assembly. The encrypted blob is left in place here —
        // the IL rewrite pass + `cleanup()` are responsible for removing
        // it together with the now-unused resolver type so the
        // ManifestResource offset_field arithmetic stays consistent.
        let new_assembly = match cil_assembly
            .into_cilobject_with(ValidationConfig::analysis(), GeneratorConfig::default())
        {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };
        assembly.replace_assembly(new_assembly);

        // The blobs the resolver decrypted now have their contents restored
        // beside them; they go with the resolver. The restored resources were
        // appended, so the blobs keep their tokens.
        for &token in &consumed {
            detection.cleanup_mut().add_manifest_resource(token);
        }

        Some(Ok(events))
    }

    fn requires_regeneration(&self) -> bool {
        true
    }
}

/// Every method of `cil_type` and of the types nested in it.
fn collect_type_methods(cil_type: &CilTypeRc) -> HashSet<Token> {
    let mut methods = HashSet::new();
    let mut stack = vec![cil_type.clone()];
    let mut visited: HashSet<Token> = std::iter::once(cil_type.token).collect();
    while let Some(ty) = stack.pop() {
        methods.extend(ty.methods().map(|method| method.token));
        for (_, nested_ref) in ty.nested_types.iter() {
            if let Some(nested) = nested_ref.upgrade() {
                if visited.insert(nested.token) {
                    stack.push(nested);
                }
            }
        }
    }
    methods
}

/// Pulls embedded `ManifestResource` rows out of every captured assembly
/// and returns `(name, data)` pairs. Resources with no accessible body
/// (offset out of range, external implementation) and empty bodies are
/// skipped — they would not round-trip back into the deobfuscated
/// output.
fn harvest_resources(captured: &[CapturedAssembly]) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for cap in captured {
        let parsed = match CilObject::from_mem_with_validation(
            cap.data.clone(),
            ValidationConfig::analysis(),
        ) {
            Ok(p) => p,
            Err(e) => {
                log::warn!(
                    "NR resources: failed to parse captured assembly ({} bytes): {e}",
                    cap.data.len()
                );
                continue;
            }
        };
        let res_table = parsed.resources();
        for entry in res_table.iter() {
            let res = entry.value();
            let Some(bytes) = res_table.get_data(res) else {
                log::debug!(
                    "NR resources: captured assembly resource {:?} has no accessible data",
                    res.name
                );
                continue;
            };
            if bytes.is_empty() {
                log::debug!(
                    "NR resources: captured assembly has empty body for {:?}",
                    res.name
                );
                continue;
            }
            out.push((res.name.to_string(), bytes.to_vec()));
        }
    }
    out
}

/// Concrete candidate produced by structural matching.
struct ResolverCandidate {
    resolver_type: CilTypeRc,
    lazy_init_token: Token,
    resolver_ctor_token: Token,
    handler_method_token: Token,
    decrypter_method_token: Token,
    dispatcher_case_count: usize,
}

/// Walks the type table looking for a type matching all four NR resource-
/// resolver signals.
fn find_resolver_candidate(assembly: &CilObject) -> Option<ResolverCandidate> {
    for type_entry in assembly.types().iter() {
        let cil_type = type_entry.value().clone();
        if let Some(c) = match_resolver_type(assembly, &cil_type) {
            return Some(c);
        }
    }
    None
}

/// Matches one type against the resolver pattern. Returns `Some` only when
/// every signal holds.
fn match_resolver_type(assembly: &CilObject, cil_type: &CilTypeRc) -> Option<ResolverCandidate> {
    // Signal 2: instance .ctor that registers a ResourceResolve / AssemblyResolve handler
    // referencing a same-type method.
    let (resolver_ctor_token, handler_method_token) =
        find_resolve_handler_registration(assembly, cil_type)?;

    // Signal 1: a static void lazy-init method whose body is the standard
    // `ldsfld bool / brtrue / set true / newobj resolver / pop / ret` shape.
    let lazy_init_token = find_lazy_init(assembly, cil_type)?;

    // Signal 3: resolver type owns a method with a massive switch dispatcher.
    let (decrypter_method_token, dispatcher_case_count) =
        find_dispatcher_method(assembly, cil_type)?;

    Some(ResolverCandidate {
        resolver_type: cil_type.clone(),
        lazy_init_token,
        resolver_ctor_token,
        handler_method_token,
        decrypter_method_token,
        dispatcher_case_count,
    })
}

/// Finds an instance `.ctor` on `cil_type` that registers a handler via
/// `AppDomain::add_ResourceResolve` (or `add_AssemblyResolve`). Returns the
/// `(ctor_token, handler_method_token)` pair.
///
/// The handler reference is identified via the `ldftn` immediately preceding
/// the `add_*Resolve` call site. The handler must live on the same type to
/// rule out user-written event handlers.
fn find_resolve_handler_registration(
    assembly: &CilObject,
    cil_type: &CilTypeRc,
) -> Option<(Token, Token)> {
    for method in cil_type.methods() {
        if method.name != wellknown::members::CTOR {
            continue;
        }
        if !method.has_body() {
            continue;
        }

        let instructions: Vec<_> = method.instructions().collect();
        let mut last_ldftn: Option<Token> = None;
        for instr in &instructions {
            match instr.mnemonic {
                "ldftn" => {
                    if let Operand::Token(t) = &instr.operand {
                        last_ldftn = Some(*t);
                    }
                }
                "callvirt" | "call" => {
                    if let Operand::Token(t) = &instr.operand {
                        let target_name = assembly.resolve_method_name(*t);
                        let is_resolve_register = target_name.as_deref().is_some_and(|n| {
                            matches!(n, "add_ResourceResolve" | "add_AssemblyResolve")
                        });
                        if is_resolve_register {
                            if let Some(handler_token) = last_ldftn {
                                if handler_lives_on_type(assembly, handler_token, cil_type) {
                                    return Some((method.token, handler_token));
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    None
}

/// Returns true when `handler_token` is a MethodDef on `cil_type`. NR's
/// handler always lives on the resolver type itself; legitimate handlers
/// almost never do.
fn handler_lives_on_type(assembly: &CilObject, handler_token: Token, cil_type: &CilTypeRc) -> bool {
    let Ok(handler) = assembly.method(&handler_token) else {
        return false;
    };
    let Some(declaring) = handler.declaring_type_rc() else {
        return false;
    };
    declaring.token == cil_type.token
}

/// Finds the `static void X()` method matching the lazy-init shape:
/// `ldsfld <bool>; brtrue; ldc.i4.1; stsfld <same bool>; newobj resolver_ctor; pop; ret`
/// (interspersed `nop`/`br.s` are tolerated).
fn find_lazy_init(assembly: &CilObject, cil_type: &CilTypeRc) -> Option<Token> {
    for method in cil_type.methods() {
        if !method.is_static() {
            continue;
        }
        if !matches!(method.signature.return_type.base, TypeSignature::Void) {
            continue;
        }
        if !method.signature.params.is_empty() {
            continue;
        }
        if !method.has_body() {
            continue;
        }
        if !is_lazy_init_body(assembly, &method, cil_type) {
            continue;
        }
        return Some(method.token);
    }
    None
}

/// Returns true if `method`'s IL matches the lazy-init shape exactly.
fn is_lazy_init_body(assembly: &CilObject, method: &MethodRc, cil_type: &CilTypeRc) -> bool {
    // Strip nop/br.s noise to match the canonical shape regardless of whether
    // the protector inserted padding.
    let instrs: Vec<_> = method
        .instructions()
        .filter(|i| !matches!(i.mnemonic, "nop" | "br" | "br.s"))
        .collect();

    let (Some(i0), Some(i1), Some(i2), Some(i3), Some(i4), Some(i5), Some(i6)) = (
        instrs.first(),
        instrs.get(1),
        instrs.get(2),
        instrs.get(3),
        instrs.get(4),
        instrs.get(5),
        instrs.get(6),
    ) else {
        return false;
    };

    let Operand::Token(flag_load) = &i0.operand else {
        return false;
    };
    if i0.mnemonic != "ldsfld" {
        return false;
    }
    if !matches!(i1.mnemonic, "brtrue" | "brtrue.s") {
        return false;
    }
    if !matches!(i2.mnemonic, "ldc.i4.1") {
        return false;
    }
    if i3.mnemonic != "stsfld" {
        return false;
    }
    let Operand::Token(flag_store) = &i3.operand else {
        return false;
    };
    if flag_load != flag_store {
        return false;
    }
    if i4.mnemonic != "newobj" {
        return false;
    }
    let Operand::Token(ctor_token) = &i4.operand else {
        return false;
    };
    // The newobj must target a .ctor on the resolver type.
    let Ok(ctor) = assembly.method(ctor_token) else {
        return false;
    };
    let Some(declaring) = ctor.declaring_type_rc() else {
        return false;
    };
    if declaring.token != cil_type.token {
        return false;
    }
    if i5.mnemonic != "pop" {
        return false;
    }
    if i6.mnemonic != "ret" {
        return false;
    }
    true
}

/// Finds a method on `cil_type` with a `switch` instruction having
/// `>= MIN_DISPATCHER_CASES` case entries. Returns the highest-case method.
///
/// The dispatcher table size is the structural fingerprint here — small
/// switches in legitimate code (state machines, opcode dispatch) bottom out
/// well under 200.
fn find_dispatcher_method(assembly: &CilObject, cil_type: &CilTypeRc) -> Option<(Token, usize)> {
    let mut best: Option<(Token, usize)> = None;
    for method in cil_type.methods() {
        if !method.has_body() {
            continue;
        }
        for instr in method.instructions() {
            if instr.mnemonic != "switch" {
                continue;
            }
            let Operand::Switch(targets) = &instr.operand else {
                continue;
            };
            let n = targets.len();
            if n >= MIN_DISPATCHER_CASES && best.as_ref().is_none_or(|(_, prev)| n > *prev) {
                best = Some((method.token, n));
            }
        }
    }
    best.filter(|(_, n)| *n >= MIN_DISPATCHER_CASES)
        .or_else(|| {
            // Defensive: also accept dispatchers detected by indirect lookup
            // (in case Operand::Switch isn't the variant the parser uses).
            // No-op fallback today — placeholder for future variants.
            let _ = assembly;
            None
        })
}

/// Lists every method whose first IL instruction is `call lazy_init`. NR
/// inserts this either as a brand-new `.cctor` (covered by
/// [`classify_purely_injected_cctors`]) or as a prepended call in `Main` and
/// each touched type's existing `.cctor`. Reported tokens are what the IL
/// rewrite pass needs to NOP.
fn find_lazy_init_call_sites(assembly: &CilObject, lazy_init_token: Token) -> Vec<Token> {
    let mut out = Vec::new();
    for entry in assembly.methods() {
        let method = entry.value();
        if method.token == lazy_init_token {
            continue;
        }
        if !method.has_body() {
            continue;
        }
        let mut iter = method.instructions();
        let Some(first) = iter.next() else { continue };
        if first.mnemonic != "call" {
            continue;
        }
        let Operand::Token(t) = &first.operand else {
            continue;
        };
        if *t == lazy_init_token {
            out.push(method.token);
        }
    }
    out
}

/// Returns tokens for `.cctor`s whose entire body is `call lazy_init; ret`
/// (with optional `nop`/`br.s` padding). These are pure injections and can be
/// deleted outright — none of the original type had a `.cctor` to preserve.
fn classify_purely_injected_cctors(assembly: &CilObject, lazy_init_token: Token) -> Vec<Token> {
    let mut out = Vec::new();
    for entry in assembly.methods() {
        let method = entry.value();
        if method.name != wellknown::members::CCTOR {
            continue;
        }
        if !method.has_body() {
            continue;
        }
        let instrs: Vec<_> = method
            .instructions()
            .filter(|i| !matches!(i.mnemonic, "nop" | "br" | "br.s"))
            .collect();
        let (Some(i0), Some(i1)) = (instrs.first(), instrs.get(1)) else {
            continue;
        };
        if instrs.len() != 2 {
            continue;
        }
        if i0.mnemonic != "call" {
            continue;
        }
        let Operand::Token(t) = &i0.operand else {
            continue;
        };
        if *t != lazy_init_token {
            continue;
        }
        if i1.mnemonic != "ret" {
            continue;
        }
        out.push(method.token);
    }
    out
}

/// Finds methods on `cil_type` (and its nested types, recursively) that
/// match the `static (Assembly) -> string[]` signature AND whose body
/// calls `Assembly::GetManifestResourceNames`. These are the
/// user-code-facing shims (e.g. `eBxqprrF8`) that the SSA rewrite pass
/// retargets to the BCL method directly.
fn find_get_manifest_resource_names_shims(
    assembly: &CilObject,
    cil_type: &CilTypeRc,
) -> Vec<Token> {
    let mut out = Vec::new();
    let mut stack = vec![cil_type.clone()];
    let mut visited: HashSet<Token> = std::iter::once(cil_type.token).collect();

    while let Some(ty) = stack.pop() {
        for method in ty.methods() {
            if !method.is_static() {
                continue;
            }
            // Returns string[] (single-dim array of String).
            let returns_string_array = match &method.signature.return_type.base {
                TypeSignature::SzArray(inner) => matches!(*inner.base, TypeSignature::String),
                _ => false,
            };
            if !returns_string_array {
                continue;
            }
            // Single Assembly-shape arg (Class, TypeRef token resolved at
            // parse time), or `object` where .NET Reactor's call hiding has
            // erased the parameter's type.
            if method.signature.params.len() != 1 {
                continue;
            }
            let Some(first_param) = method.signature.params.first() else {
                continue;
            };
            if !matches!(
                first_param.base,
                TypeSignature::Class(_) | TypeSignature::Object
            ) {
                continue;
            }
            if !method.has_body() {
                continue;
            }
            // Body must reference `GetManifestResourceNames` by name on a
            // BCL MemberRef. Avoids matching unrelated user methods that
            // happen to take an Assembly and return string[].
            let mut calls_bcl = false;
            for instr in method.instructions() {
                if !matches!(instr.mnemonic, "callvirt" | "call") {
                    continue;
                }
                if let Some(t) = instr.get_token_operand() {
                    if let Some(name) = assembly.resolve_method_name(t) {
                        if name == "GetManifestResourceNames" {
                            calls_bcl = true;
                            break;
                        }
                    }
                }
            }
            if calls_bcl {
                out.push(method.token);
            }
        }
        for (_, nested_ref) in ty.nested_types.iter() {
            if let Some(nested) = nested_ref.upgrade() {
                if visited.insert(nested.token) {
                    stack.push(nested);
                }
            }
        }
    }
    out.sort_by_key(|t| t.value());
    out
}

/// Finds the `MemberRef` for method `method_name` of the core library type
/// `type_fullname` and returns its token.
///
/// Used by detection to resolve the BCL `MemberRef` for
/// `Assembly::GetManifestResourceNames` so the SSA rewrite pass can
/// retarget shim calls without inventing new metadata. Every NR
/// resources sample observed already references that BCL method from
/// inside the resolver type body, so the lookup succeeds in practice.
fn find_bcl_member_ref(
    assembly: &CilObject,
    type_fullname: &str,
    method_name: &str,
) -> Option<Token> {
    let parent = assembly.types().get_corelib_typeref(type_fullname)?.token;
    assembly
        .refs_members()
        .iter()
        .map(|entry| entry.value().clone())
        .find(|mref| {
            mref.name == method_name
                && matches!(&mref.declaredby, CilTypeReference::TypeRef(r) if r.token() == Some(parent))
        })
        .map(|mref| mref.token)
}

/// Looks up the TypeRef token for the core library's
/// `System.Reflection.Assembly` in the given assembly. NR shifts the TypeRef
/// ordering when it injects new rows, so the BCL hook's hardcoded token can
/// collide with unrelated rows; this helper resolves the live token.
///
/// Returns `None` only when the assembly does not import
/// `System.Reflection.Assembly` at all, which would mean the resource
/// resolver pattern itself isn't present. Used by
/// [`hooks::create_resources_load_shim_hook`]
/// to anchor the fake Assembly object's type to the current sample.
pub fn find_assembly_typeref(assembly: &CilObject) -> Option<Token> {
    assembly
        .types()
        .get_corelib_typeref("System.Reflection.Assembly")
        .map(|ty| ty.token)
}

/// Finds methods on `cil_type` (and its nested types, recursively) whose
/// signature is `(uint8[]) -> object` AND whose IL body contains the
/// reflective `Assembly::Load` invocation pattern:
///
/// 1. `ldtoken` for `[mscorlib]System.Reflection.Assembly`
/// 2. `Type::GetTypeFromHandle`
/// 3. A subsequent `MethodBase::Invoke` (or `MethodInfo::Invoke`)
///
/// Matched methods are hooked during emulation so the byte-array argument
/// gets captured even though the in-emulator `Type.GetMethod` BCL stub
/// can't currently resolve `Assembly::Load` against a real BCL Type.
fn find_assembly_load_shim_methods(
    assembly: &CilObject,
    cil_type: &CilTypeRc,
    type_handle_accessors: &[Token],
) -> Vec<Token> {
    let mut out = Vec::new();
    let mut stack = vec![cil_type.clone()];
    let mut visited: HashSet<Token> = std::iter::once(cil_type.token).collect();

    while let Some(ty) = stack.pop() {
        for method in ty.methods() {
            if !method.is_static() {
                continue;
            }
            // Returns Object (Class/Object/etc.) is the broad shape; we'll
            // tighten via the IL pattern match below.
            if !matches!(
                method.signature.return_type.base,
                TypeSignature::Object | TypeSignature::Class(_)
            ) {
                continue;
            }
            if method.signature.params.len() != 1 {
                continue;
            }
            let Some(param) = method.signature.params.first() else {
                continue;
            };
            // The assembly bytes, or an `object` where .NET Reactor's call
            // hiding has erased the parameter's type.
            let takes_bytes = match &param.base {
                TypeSignature::SzArray(inner) => matches!(*inner.base, TypeSignature::U1),
                TypeSignature::Object => true,
                _ => false,
            };
            if !takes_bytes {
                continue;
            }
            if !method.has_body() {
                continue;
            }
            if !is_assembly_load_reflection_shim(&method, assembly, type_handle_accessors) {
                continue;
            }
            out.push(method.token);
        }
        for (_, nested_ref) in ty.nested_types.iter() {
            if let Some(nested) = nested_ref.upgrade() {
                if visited.insert(nested.token) {
                    stack.push(nested);
                }
            }
        }
    }

    // Stable order keeps the hook deterministic across runs (registration
    // order in the emulator can affect priority resolution).
    out.sort_by_key(|t| t.value());
    let _ = assembly;
    out
}

/// Returns true when `method` looks like an `Assembly.Load(byte[])`
/// reflective wrapper: the body loads a type token AND eventually calls a
/// method named `Invoke` (resolved through the assembly's MemberRef table
/// rather than text-matching the operand). Pairing the two signals on a
/// method that already passed the `(uint8[]) -> object` signature gate is
/// strong enough: no legitimate static `(byte[]) -> object` method on a
/// resolver-shape type does both.
///
/// The type token is an `ldtoken`, or, where anti-tamper has rewritten every
/// `ldtoken` into a raw token passed to its metadata-token resolver, a call to
/// one of that resolver's `type_handle_accessors`.
fn is_assembly_load_reflection_shim(
    method: &MethodRc,
    assembly: &CilObject,
    type_handle_accessors: &[Token],
) -> bool {
    let mut saw_assembly_token = false;
    let mut saw_invoke_call = false;
    for instr in method.instructions() {
        if instr.mnemonic == "ldtoken" {
            if let Operand::Token(_) = &instr.operand {
                saw_assembly_token = true;
            }
        }
        if instr.mnemonic == "call" {
            if let Operand::Token(t) = &instr.operand {
                if type_handle_accessors.contains(t) {
                    saw_assembly_token = true;
                }
            }
        }
        if matches!(instr.mnemonic, "callvirt" | "call") {
            if let Operand::Token(t) = &instr.operand {
                if let Some(name) = assembly.resolve_method_name(*t) {
                    if name == "Invoke" {
                        saw_invoke_call = true;
                    }
                }
            }
        }
        if saw_assembly_token && saw_invoke_call {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {

    use std::sync::Arc;

    use super::*;
    use crate::{
        emulation::EmulationOutcome,
        testkit::{emulation::process_builder, load_sample},
    };

    #[test]
    fn test_detect_positive_reactor_resources() {
        let assembly = load_sample("packers/netreactor/7.5.0/reactor_resources.exe");
        let detection = NetReactorResources.detect(&assembly);
        assert!(
            detection.is_detected(),
            "Should detect resource encryption in reactor_resources.exe"
        );
        let findings = detection
            .findings::<ResourceFindings>()
            .expect("Should attach findings");
        assert!(
            !findings.encrypted_resource_tokens.is_empty(),
            "Should mark at least one encrypted resource"
        );
        assert!(
            !findings.lazy_init_call_sites.is_empty(),
            "Should locate at least one lazy-init injection site"
        );
        // Every NR sample with this stage observed so far has at least one
        // purely-injected .cctor (the protector adds one to `Program`).
        assert!(
            !findings.purely_injected_cctors.is_empty(),
            "Should classify at least one purely-injected .cctor"
        );
        assert!(
            !findings.assembly_load_shim_tokens.is_empty(),
            "Should locate at least one Assembly.Load reflection shim ({} found)",
            findings.assembly_load_shim_tokens.len()
        );
        assert!(
            !findings.get_manifest_resource_names_shim_tokens.is_empty(),
            "Should locate at least one GetManifestResourceNames shim ({} found)",
            findings.get_manifest_resource_names_shim_tokens.len()
        );
        eprintln!(
            "Resolver type 0x{:08X}, decrypter 0x{:08X}, lazy init 0x{:08X}, \
             ctor 0x{:08X}, handler 0x{:08X}, {} load shims, {} GMRN shims, \
             {} encrypted resources, BCL GMRN MemberRef = 0x{:08X}",
            findings.resolver_type_token.value(),
            findings.decrypter_method_token.value(),
            findings.lazy_init_token.value(),
            findings.resolver_ctor_token.value(),
            findings.handler_method_token.value(),
            findings.assembly_load_shim_tokens.len(),
            findings.get_manifest_resource_names_shim_tokens.len(),
            findings.encrypted_resource_tokens.len(),
            findings.bcl_get_manifest_resource_names.value(),
        );
        for t in &findings.assembly_load_shim_tokens {
            eprintln!("  shim: 0x{:08X}", t.value());
        }
    }

    #[test]
    fn string_encrypted_resource_names_do_not_hide_the_resolver() {
        // With string encryption on, no `ldstr` names the encrypted blob; the
        // resolver is still found by its structure, and the transform learns
        // the blob from what the decrypter opens.
        for name in &["reactor_full.exe", "reactor_virtualization_full.exe"] {
            let assembly = load_sample(&format!("packers/netreactor/7.5.0/{name}"));
            let detection = NetReactorResources.detect(&assembly);
            assert!(detection.is_detected(), "{name} encrypts its resources");
        }
    }

    #[test]
    fn test_detect_negative_baseline() {
        let assembly = load_sample("packers/netreactor/7.5.0/original.exe");
        let detection = NetReactorResources.detect(&assembly);
        assert!(
            !detection.is_detected(),
            "Should not detect in unprotected original.exe"
        );
    }

    /// The resource decrypter, emulated on its own, yields the protected program's resources:
    /// the assembly it hands to `Assembly.Load` holds every resource of the unprotected build,
    /// byte for byte.
    #[test]
    fn emulating_the_decrypter_yields_the_original_resources() {
        let assembly = load_sample("packers/netreactor/7.5.0/reactor_resources.exe");
        let detection = NetReactorResources.detect(&assembly);
        assert!(detection.is_detected(), "detection should fire");
        let findings = detection.findings::<ResourceFindings>().unwrap();

        let cilobject = Arc::new(assembly);
        let mut builder = process_builder()
            .assembly_arc(Arc::clone(&cilobject))
            .name("nr-resources")
            .with_max_instructions(80_000_000)
            .with_max_call_depth(300)
            .capture_assemblies();
        // Hook the resolver's reflective Assembly.Load shims so the byte[] is captured
        // whatever shape it arrives in.
        if !findings.assembly_load_shim_tokens.is_empty() {
            let shim_set: HashSet<Token> =
                findings.assembly_load_shim_tokens.iter().copied().collect();
            let asm_typeref =
                find_assembly_typeref(&cilobject).expect("Assembly TypeRef must exist");
            builder = builder.hook(hooks::create_resources_load_shim_hook(
                shim_set,
                asm_typeref,
            ));
        }
        let process = builder.build().expect("process build");

        let outcome = process
            .execute_method(findings.decrypter_method_token, vec![])
            .expect("the decrypter runs");
        assert!(
            matches!(outcome, EmulationOutcome::Completed { .. }),
            "the decrypter completes: {outcome}"
        );
        let captured = process.capture().assemblies();
        assert_eq!(captured.len(), 1, "one resource assembly is loaded");
        let resources = CilObject::from_mem(captured[0].data.clone()).expect("it parses");

        let original = load_sample("packers/netreactor/7.5.0/original.exe");
        assert!(!original.resources().is_empty());
        for entry in original.resources().iter() {
            let expected = entry.value();
            let found = resources
                .resources()
                .get(&expected.name)
                .unwrap_or_else(|| panic!("{} is missing", expected.name));
            assert_eq!(
                resources.resources().get_data(&found),
                original.resources().get_data(expected),
                "{} differs",
                expected.name
            );
        }
    }

    #[test]
    fn test_detect_negative_no_resources_nr() {
        // Samples with NR but no resource encryption must not fire.
        for name in &[
            "reactor_obfuscation.exe",
            "reactor_strings.exe",
            "reactor_necrobit.exe",
            "reactor_antitamp.exe",
        ] {
            let assembly = load_sample(&format!("packers/netreactor/7.5.0/{name}"));
            let detection = NetReactorResources.detect(&assembly);
            assert!(
                !detection.is_detected(),
                "Should not fire on {name} (no resource resolver)"
            );
        }
    }
}
