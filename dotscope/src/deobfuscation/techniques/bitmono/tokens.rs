//! BitMono's stale method tokens.
//!
//! BitMono writes the protected module with AsmResolver and `MetadataBuilderFlags.None`, and
//! that write renumbers the MethodDef table. Two protections embed method tokens as `ldc.i4`
//! integers taken from the module as loaded, before the write, so the write does not
//! renumber them:
//!
//! - DotNetHook's init methods: `ldc.i4 <dummy>; ldc.i4 <target>; call RedirectStub`.
//! - CallToCalli's call sites: `ldc.i4 <target>; call Module::ResolveMethod; ... calli`.
//!
//! A target token is the row the method had in the unprotected input. A dummy token is a row
//! BitMono allocated past the input's rows; the dummy itself is the method right before its
//! init method in `<Module>`.
//!
//! # Where an input row went
//!
//! The write emits each type's methods together, in their list order, and BitMono only ever
//! appends to a list. A type's methods from the input are therefore the first ones of its run
//! in the protected file, in their input order: they all moved by one offset, the type's own.
//! Each embedded target token comes with the signature of the method it names (the hook
//! dummy's, which DotNetHook derives from the target's, or the `calli` site's), and the
//! offsets are those under which every token names a method of its signature. A token that no
//! single assignment of offsets explains is not resolved, and the transform fails rather than
//! guess.

use std::{
    any::Any,
    collections::{BTreeMap, BTreeSet, HashMap},
};

use crate::{
    assembly::Instruction,
    compiler::{EventKind, EventLog},
    deobfuscation::techniques::{
        bitmono::hooks::{
            dummy_admits, dummy_of, find_redirect_stub, init_pairs, is_resolve_method_call,
        },
        Detection, Evidence, Technique, TechniqueCapability, TechniqueCategory, WorkingAssembly,
    },
    metadata::{
        method::Method,
        signatures::SignatureMethod,
        tables::{StandAloneSigRaw, StandAloneSignature, TableId},
        token::Token,
    },
    CilObject, Error, Result,
};

/// The most solutions searched before the rows count as ambiguous.
const SOLUTION_LIMIT: usize = 64;

/// The most assignments tried before the rows count as ambiguous, which bounds the search on
/// rows whose candidates keep failing late.
const STEP_LIMIT: usize = 1_000_000;

/// The number of BitMono method tokens embedded in an assembly.
#[derive(Debug)]
pub struct TokenFindings {
    /// DotNetHook init methods.
    pub hooks: usize,
    /// CallToCalli call sites.
    pub calli_sites: usize,
}

/// A method token BitMono embedded as an `ldc.i4` operand.
#[derive(Debug, Clone)]
struct Embedded {
    /// The file offset of the operand.
    operand: u64,
    /// The token the operand holds.
    token: u32,
    /// What the token names.
    names: Names,
}

/// What an embedded token names.
#[derive(Debug, Clone)]
enum Names {
    /// The dummy of a DotNetHook init method: the method before the init method.
    HookDummy(Token),
    /// The target of a DotNetHook init method whose dummy has this signature.
    HookTarget(SignatureMethod),
    /// The method a CallToCalli site calls, through a `calli` of this signature.
    CalliTarget(SignatureMethod),
}

impl Names {
    /// Whether `method` is one the token may name.
    fn admits(&self, method: &Method) -> bool {
        match self {
            Names::HookDummy(dummy) => method.token == *dummy,
            Names::HookTarget(dummy) => dummy_admits(dummy, method),
            Names::CalliTarget(site) => {
                site.has_this != method.is_static() && site.has_same_shape(&method.signature)
            }
        }
    }
}

/// The method tokens BitMono embedded in `assembly`, with what each names.
///
/// # Errors
///
/// [`Error::Deobfuscation`] when an embedded token is not in the shape BitMono writes it: a hook
/// with no dummy before its init method, or a `ResolveMethod` call with no `calli` of the
/// function pointer it yields. Such a token cannot be resolved, and leaving it would have later
/// passes read a row it does not name.
fn embedded_tokens(assembly: &CilObject) -> Result<Vec<Embedded>> {
    let mut embedded = Vec::new();
    if let Some(stub) = find_redirect_stub(assembly) {
        for pair in init_pairs(assembly, stub) {
            let dummy = dummy_of(assembly, pair.init)
                .and_then(|dummy| assembly.method(&dummy).ok())
                .ok_or_else(|| {
                    Error::Deobfuscation(format!(
                        "DotNetHook init method {} has no dummy before it",
                        pair.init
                    ))
                })?;
            embedded.push(Embedded {
                operand: pair.dummy_operand,
                token: pair.dummy,
                names: Names::HookDummy(dummy.token),
            });
            embedded.push(Embedded {
                operand: pair.target_operand,
                token: pair.target,
                names: Names::HookTarget(dummy.signature.clone()),
            });
        }
    }

    for method_entry in assembly.methods() {
        let method = method_entry.value();
        let instructions: Vec<&Instruction> = method.instructions().collect();
        for (i, instr) in instructions.iter().enumerate() {
            if instr.mnemonic != "ldc.i4"
                || !instructions
                    .get(i.saturating_add(1))
                    .is_some_and(|next| is_resolve_method_call(assembly, next))
            {
                continue;
            }
            let Some(token) = instr.get_i32_operand().map(i32::cast_unsigned) else {
                continue;
            };
            // CallToCalli loads the function pointer with GetFunctionPointer and calls it with
            // the next `calli`: a `calli` takes its arguments before its function pointer, so
            // whatever later protections put in between leaves the stack as it was.
            let site = instructions
                .iter()
                .skip(i.saturating_add(2))
                .skip_while(|instr| !is_get_function_pointer_call(assembly, instr))
                .skip(1)
                .find(|instr| instr.mnemonic == "calli")
                .and_then(|calli| calli.get_token_operand())
                .and_then(|sig| calli_signature(assembly, sig))
                .ok_or_else(|| {
                    Error::Deobfuscation(format!(
                        "{} resolves method token 0x{token:08X} at RVA 0x{:08X} with no calli of \
                         its function pointer",
                        method.token, instr.rva
                    ))
                })?;
            embedded.push(Embedded {
                operand: instr.offset.saturating_add(1),
                token,
                names: Names::CalliTarget(site),
            });
        }
    }
    Ok(embedded)
}

/// Whether `instr` calls `System.RuntimeMethodHandle::GetFunctionPointer`.
fn is_get_function_pointer_call(assembly: &CilObject, instr: &Instruction) -> bool {
    instr.mnemonic == "call"
        && instr
            .get_token_operand()
            .and_then(|token| assembly.member_ref(&token))
            .is_some_and(|member| {
                member.name == "GetFunctionPointer"
                    && member
                        .declaredby
                        .fullname()
                        .is_some_and(|t| t == "System.RuntimeMethodHandle")
            })
}

/// The method signature of a `calli` site's StandAloneSig.
fn calli_signature(assembly: &CilObject, token: Token) -> Option<SignatureMethod> {
    if token.table() != TableId::StandAloneSig as u8 {
        return None;
    }
    let raw = assembly
        .tables()?
        .table::<StandAloneSigRaw>()?
        .get(token.row())
        .ok()
        .flatten()?;
    match &raw.to_owned(assembly.blob()?).ok()?.parsed_signature {
        StandAloneSignature::Method(signature) => Some(signature.clone()),
        _ => None,
    }
}

/// Where each embedded token's method is in `assembly`: the token to write in its place.
///
/// # Errors
///
/// [`Error::Deobfuscation`] naming the tokens the embedded signatures do not pin down.
fn resolve(assembly: &CilObject, embedded: &[Embedded]) -> Result<Vec<(u64, u32)>> {
    // A token holding a dummy's stale row names that dummy wherever it is embedded, a
    // CallToCalli site included (DotNetHook ran first and CallToCalli rewrote its call).
    let dummies: HashMap<u32, Token> = embedded
        .iter()
        .filter_map(|e| match e.names {
            Names::HookDummy(dummy) => Some((e.token, dummy)),
            _ => None,
        })
        .collect();

    // What each stale target row must look like, from every place it is embedded.
    let mut constraints: BTreeMap<u32, Vec<&Names>> = BTreeMap::new();
    for e in embedded {
        if !matches!(e.names, Names::HookDummy(_)) && !dummies.contains_key(&e.token) {
            constraints.entry(e.token).or_default().push(&e.names);
        }
    }

    // Methods BitMono added cannot be a target: the hooks' dummies and init methods.
    let injected: BTreeSet<Token> = find_redirect_stub(assembly)
        .map(|stub| {
            init_pairs(assembly, stub)
                .iter()
                .flat_map(|pair| [Some(pair.init), dummy_of(assembly, pair.init)])
                .flatten()
                .collect()
        })
        .unwrap_or_default();

    let mut candidates: BTreeMap<u32, Vec<(Token, Token)>> = BTreeMap::new();
    for (&row, names) in &constraints {
        // A token outside the MethodDef table names no input method; it stays unresolved.
        if row >> 24 != u32::from(TableId::MethodDef as u8) {
            candidates.insert(row, Vec::new());
            continue;
        }
        let admitted = assembly
            .methods()
            .iter()
            .filter_map(|entry| {
                let method = entry.value();
                let declaring = method.declaring_type_rc()?.token;
                (!injected.contains(&method.token) && names.iter().all(|n| n.admits(method)))
                    .then_some((method.token, declaring))
            })
            .collect();
        candidates.insert(row, admitted);
    }

    let module = assembly.types().module_type().map(|module| module.token);
    let mut extents: HashMap<Token, Extent> = HashMap::new();
    for entry in assembly.methods().iter() {
        let method = entry.value();
        let Some(declaring) = method.declaring_type_rc().map(|declaring| declaring.token) else {
            continue;
        };
        let row = method.token.row();
        let extent = extents.entry(declaring).or_insert(Extent {
            first: row,
            count: 0,
            module: Some(declaring) == module,
        });
        extent.first = extent.first.min(row);
        extent.count = extent.count.saturating_add(1);
    }
    // DotNetHook allocated its dummies' rows past every input row.
    let limit = dummies.keys().map(|token| token & 0x00FF_FFFF).min();

    let (resolved, unresolved) = solve(&candidates, &extents, limit);
    if !unresolved.is_empty() {
        let rows: Vec<String> = unresolved.iter().map(|t| format!("0x{t:08X}")).collect();
        return Err(Error::Deobfuscation(format!(
            "BitMono embedded method tokens {} name no method their signatures pin down",
            rows.join(", ")
        )));
    }

    Ok(embedded
        .iter()
        .filter_map(|e| {
            let token = match e.names {
                Names::HookDummy(dummy) => dummy,
                _ => dummies
                    .get(&e.token)
                    .or_else(|| resolved.get(&e.token))
                    .copied()?,
            };
            (token.value() != e.token).then_some((e.operand, token.value()))
        })
        .collect())
}

/// Where a type's methods are in the protected file.
#[derive(Debug, Clone, Copy)]
struct Extent {
    /// The row of its first method.
    first: u32,
    /// The number of its methods.
    count: u32,
    /// Whether it is `<Module>`, the one type BitMono adds methods to.
    module: bool,
}

/// Assigns each stale row the method it names: one of its candidates, such that
///
/// - every row assigned to a type moved by the same offset, the type's;
/// - the input rows the types held under their offsets do not overlap: BitMono adds methods
///   only to `<Module>`, so any other type held exactly its methods, moved by its offset,
///   and `<Module>`'s own input methods lead its list and did not move;
/// - every input row is below `limit`, the first row BitMono allocated past the input.
///
/// A row is resolved when every such assignment gives it the same method.
///
/// # Arguments
///
/// * `candidates` - Each stale row's admitted methods, with their declaring types.
/// * `extents` - Where each declaring type's methods are in the protected file.
/// * `limit` - The first row past the input's rows, when known.
///
/// # Returns
///
/// The method of each resolved row, and the rows left unresolved.
fn solve(
    candidates: &BTreeMap<u32, Vec<(Token, Token)>>,
    extents: &HashMap<Token, Extent>,
    limit: Option<u32>,
) -> (HashMap<u32, Token>, BTreeSet<u32>) {
    let mut rows: Vec<u32> = candidates.keys().copied().collect();
    // Fewest candidates first prunes the search soonest.
    rows.sort_by_key(|row| candidates.get(row).map_or(0, Vec::len));
    let mut search = Search {
        candidates,
        extents,
        limit,
        rows: &rows,
        held: HashMap::new(),
        assignment: HashMap::new(),
        solutions: Vec::new(),
        steps: 0,
    };
    search.run(0);

    let mut resolved = HashMap::new();
    let mut unresolved = BTreeSet::new();
    if search.solutions.is_empty()
        || search.solutions.len() > SOLUTION_LIMIT
        || search.steps > STEP_LIMIT
    {
        unresolved.extend(rows.iter().copied());
        return (resolved, unresolved);
    }
    for &row in &rows {
        let mut methods = search.solutions.iter().map(|s| s.get(&row).copied());
        match methods.next().flatten() {
            Some(first) if methods.all(|m| m == Some(first)) => {
                resolved.insert(row, first);
            }
            _ => {
                unresolved.insert(row);
            }
        }
    }
    (resolved, unresolved)
}

/// The offset a type moved by and the input rows it held, `lo..=hi`.
#[derive(Debug, Clone, Copy)]
struct Held {
    offset: i64,
    lo: i64,
    hi: i64,
}

/// A backtracking search for the assignments of the stale rows.
struct Search<'a> {
    candidates: &'a BTreeMap<u32, Vec<(Token, Token)>>,
    extents: &'a HashMap<Token, Extent>,
    limit: Option<u32>,
    rows: &'a [u32],
    /// What each type holds under the assignment so far.
    held: HashMap<Token, Held>,
    assignment: HashMap<u32, Token>,
    solutions: Vec<HashMap<u32, Token>>,
    /// The assignments tried so far.
    steps: usize,
}

impl Search<'_> {
    /// What `declaring` holds once `row` is assigned its method `method`, if that is consistent
    /// with what every type holds so far.
    fn hold(&self, row: u32, method: Token, declaring: Token) -> Option<Held> {
        let extent = self.extents.get(&declaring)?;
        let row = i64::from(row & 0x00FF_FFFF);
        let offset = i64::from(method.row()).saturating_sub(row);
        let held = match (self.held.get(&declaring), extent.module) {
            (Some(held), _) if held.offset != offset => return None,
            (Some(held), true) => Held {
                hi: held.hi.max(row),
                ..*held
            },
            (Some(held), false) => *held,
            (None, true) if offset != 0 => return None,
            (None, true) => Held {
                offset,
                lo: 1,
                hi: row,
            },
            (None, false) => {
                let lo = i64::from(extent.first).saturating_sub(offset);
                Held {
                    offset,
                    lo,
                    hi: lo.saturating_add(i64::from(extent.count)).saturating_sub(1),
                }
            }
        };
        let within = held.lo >= 1 && self.limit.is_none_or(|limit| held.hi < i64::from(limit));
        let apart = self
            .held
            .iter()
            .all(|(other, h)| *other == declaring || h.hi < held.lo || held.hi < h.lo);
        (within && apart).then_some(held)
    }

    fn run(&mut self, next: usize) {
        if self.solutions.len() > SOLUTION_LIMIT || self.steps > STEP_LIMIT {
            return;
        }
        self.steps = self.steps.saturating_add(1);
        let Some(&row) = self.rows.get(next) else {
            self.solutions.push(self.assignment.clone());
            return;
        };
        for &(method, declaring) in self.candidates.get(&row).into_iter().flatten() {
            let Some(held) = self.hold(row, method, declaring) else {
                continue;
            };
            let before = self.held.insert(declaring, held);
            self.assignment.insert(row, method);
            self.run(next.saturating_add(1));
            self.assignment.remove(&row);
            match before {
                Some(before) => self.held.insert(declaring, before),
                None => self.held.remove(&declaring),
            };
        }
    }
}

/// Rewrites the method tokens BitMono embedded to the rows their methods have in the
/// protected file.
///
/// DotNetHook and CallToCalli embed tokens of the module before BitMono wrote it; the write
/// renumbered the MethodDef table and left these integers behind. Every later reading of them
/// (hook reversal, `calli` devirtualization) needs them to name the methods they named.
pub struct BitMonoTokens;

impl Technique for BitMonoTokens {
    fn id(&self) -> &'static str {
        "bitmono.tokens"
    }

    fn name(&self) -> &'static str {
        "BitMono Stale Method Tokens"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Structure
    }

    fn capabilities(&self) -> Vec<TechniqueCapability> {
        vec![TechniqueCapability::ByteTransform]
    }

    fn detect(&self, assembly: &CilObject) -> Detection {
        let embedded = match embedded_tokens(assembly) {
            Ok(embedded) => embedded,
            // Detected all the same: the transform reports what it cannot resolve.
            Err(e) => {
                return Detection::new_detected(vec![Evidence::Structural(e.to_string())], None)
            }
        };
        let hooks = embedded
            .iter()
            .filter(|e| matches!(e.names, Names::HookDummy(_)))
            .count();
        let calli_sites = embedded
            .iter()
            .filter(|e| matches!(e.names, Names::CalliTarget(_)))
            .count();
        if hooks == 0 && calli_sites == 0 {
            return Detection::new_empty();
        }
        Detection::new_detected(
            vec![Evidence::BytecodePattern(format!(
                "{hooks} DotNetHook init methods and {calli_sites} CallToCalli sites embed \
                 method tokens as integers"
            ))],
            Some(Box::new(TokenFindings { hooks, calli_sites }) as Box<dyn Any + Send + Sync>),
        )
    }

    fn byte_transform(
        &self,
        assembly: &mut WorkingAssembly,
        _detection: &mut Detection,
    ) -> Option<Result<EventLog>> {
        let events = EventLog::new();
        let co = match assembly.cilobject() {
            Ok(co) => co,
            Err(e) => return Some(Err(e)),
        };
        let embedded = match embedded_tokens(co) {
            Ok(embedded) => embedded,
            Err(e) => return Some(Err(e)),
        };
        let patches = match resolve(co, &embedded) {
            Ok(patches) => patches,
            Err(e) => return Some(Err(e)),
        };

        for &(operand, token) in &patches {
            let Ok(operand) = usize::try_from(operand) else {
                return Some(Err(Error::Deobfuscation(format!(
                    "embedded token operand at 0x{operand:X} exceeds the address space"
                ))));
            };
            if let Err(e) = assembly.write_le::<u32>(operand, token) {
                return Some(Err(e));
            }
        }

        events.record(EventKind::ArtifactRemoved).message(format!(
            "Rewrote {} of {} embedded method tokens to the rows BitMono's write moved them to",
            patches.len(),
            embedded.len()
        ));
        Some(Ok(events))
    }

    fn requires_regeneration(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        deobfuscation::techniques::bitmono::hooks::find_redirect_stub,
        testkit::helpers::load_sample,
    };

    /// The method `original` has at `row`, by declaring type and name.
    fn method_named(original: &CilObject, row: u32) -> (String, String) {
        let method = original
            .method(&Token::from_parts(TableId::MethodDef, row))
            .expect("an input row");
        let declaring = method
            .declaring_type_rc()
            .map(|t| t.fullname().to_string())
            .unwrap_or_default();
        (declaring, method.name.to_string())
    }

    #[test]
    fn every_hook_target_resolves_to_the_method_the_input_had_at_its_row() {
        // The dotnethook samples keep the input's type and method names, so the unprotected
        // input names each target row independently of the protected file's layout.
        for version in ["0.39.0", "0.45.0"] {
            let dir = format!("packers/bitmono/{version}");
            let protected = load_sample(&format!("{dir}/bitmono_dotnethook.exe"));
            let original = load_sample(&format!("{dir}/original.exe"));

            let embedded = embedded_tokens(&protected).expect("every token in BitMono's shape");
            let patches: HashMap<u64, u32> = resolve(&protected, &embedded)
                .expect("resolves")
                .into_iter()
                .collect();
            let stub = find_redirect_stub(&protected).expect("RedirectStub");
            for pair in init_pairs(&protected, stub) {
                let target = patches
                    .get(&pair.target_operand)
                    .copied()
                    .unwrap_or(pair.target);
                let resolved = protected.method(&Token::new(target)).expect("resolved");
                let declaring = resolved
                    .declaring_type_rc()
                    .map(|t| t.fullname().to_string())
                    .unwrap_or_default();
                assert_eq!(
                    (declaring, resolved.name.to_string()),
                    method_named(&original, pair.target & 0x00FF_FFFF),
                    "{version}: init {} target 0x{:08X}",
                    pair.init,
                    pair.target
                );
            }
        }
    }

    /// What a method is, renaming aside: its position among its type's methods, their number,
    /// whether it is static, and its number of parameters.
    fn shape(assembly: &CilObject, token: Token) -> (usize, usize, bool, usize) {
        let method = assembly.method(&token).expect("a method");
        let declaring = method.declaring_type_rc().expect("a declaring type");
        let mut rows: Vec<u32> = declaring
            .methods
            .iter()
            .filter_map(|(_, m)| m.upgrade().map(|m| m.token.row()))
            .collect();
        rows.sort_unstable();
        let position = rows
            .iter()
            .position(|&row| row == token.row())
            .expect("listed by its type");
        (
            position,
            rows.len(),
            method.is_static(),
            method.signature.params.len(),
        )
    }

    #[test]
    fn every_embedded_token_resolves_to_the_method_the_input_had_at_its_row() {
        // FullRenamer renames the maximum samples, but a method's place among its type's
        // methods, their number and its signature's arity survive it. Every embedded token,
        // CallToCalli's included (one of which AntiDebugBreakpoints separates from its calli),
        // must resolve to the method of that shape at the input's row.
        for version in ["0.39.0", "0.45.0"] {
            let dir = format!("packers/bitmono/{version}");
            let original = load_sample(&format!("{dir}/original.exe"));
            for sample in ["bitmono_maximum", "bitmono_maximum_il", "bitmono_combined"] {
                let protected = load_sample(&format!("{dir}/{sample}.exe"));
                let embedded = embedded_tokens(&protected).expect("every token in BitMono's shape");
                assert!(
                    embedded
                        .iter()
                        .any(|e| matches!(e.names, Names::CalliTarget(_))),
                    "{version} {sample}: CallToCalli sites"
                );
                let patches: HashMap<u64, u32> = resolve(&protected, &embedded)
                    .expect("resolves")
                    .into_iter()
                    .collect();
                for e in &embedded {
                    if matches!(e.names, Names::HookDummy(_)) {
                        continue;
                    }
                    let resolved = patches.get(&e.operand).copied().unwrap_or(e.token);
                    let Ok(input) = original.method(&Token::new(e.token)) else {
                        // A dummy's row: DotNetHook ran before CallToCalli.
                        continue;
                    };
                    assert_eq!(
                        shape(&protected, Token::new(resolved)),
                        shape(&original, input.token),
                        "{version} {sample}: 0x{:08X} resolved to 0x{resolved:08X}",
                        e.token
                    );
                }
            }
        }
    }

    /// A type whose methods are the `count` rows from `first`.
    fn extent(first: u32, count: u32) -> Extent {
        Extent {
            first,
            count,
            module: false,
        }
    }

    #[test]
    fn a_row_its_signatures_do_not_pin_down_is_not_guessed() {
        // Three methods of one type share a signature; one row naming one of them, with no
        // other row of the type to fix its offset, could be any of the three.
        let declaring = Token::new(0x0200_0005);
        let candidates: BTreeMap<u32, Vec<(Token, Token)>> = [(
            0x0600_0010,
            vec![
                (Token::new(0x0600_0050), declaring),
                (Token::new(0x0600_0051), declaring),
                (Token::new(0x0600_0052), declaring),
            ],
        )]
        .into_iter()
        .collect();
        let extents = [(declaring, extent(0x50, 3))].into_iter().collect();
        let (resolved, unresolved) = solve(&candidates, &extents, None);
        assert!(resolved.is_empty());
        assert_eq!(
            unresolved.into_iter().collect::<Vec<_>>(),
            vec![0x0600_0010]
        );
    }

    #[test]
    fn rows_of_one_type_share_its_offset() {
        // The same three methods, each named by its own row: only one offset fits all three.
        let declaring = Token::new(0x0200_0005);
        let methods = vec![
            (Token::new(0x0600_0050), declaring),
            (Token::new(0x0600_0051), declaring),
            (Token::new(0x0600_0052), declaring),
        ];
        let candidates: BTreeMap<u32, Vec<(Token, Token)>> =
            [0x0600_0010, 0x0600_0011, 0x0600_0012]
                .into_iter()
                .map(|row| (row, methods.clone()))
                .collect();
        let extents = [(declaring, extent(0x50, 3))].into_iter().collect();
        let (resolved, unresolved) = solve(&candidates, &extents, None);
        assert!(unresolved.is_empty());
        assert_eq!(resolved.get(&0x0600_0010), Some(&Token::new(0x0600_0050)));
        assert_eq!(resolved.get(&0x0600_0012), Some(&Token::new(0x0600_0052)));
    }

    #[test]
    fn a_row_cannot_move_into_a_type_whose_input_rows_another_type_held() {
        // Type A's rows 0x10 and 0x11 pin its offset to 0x40: it held input rows 0x10..=0x12.
        // Row 0x12 fits A's third method, and also type B's only method, whose offset would
        // then make B hold input row 0x12 too. Only A can have held it.
        let a = Token::new(0x0200_0002);
        let b = Token::new(0x0200_0003);
        let candidates: BTreeMap<u32, Vec<(Token, Token)>> = [
            (0x0600_0010, vec![(Token::new(0x0600_0050), a)]),
            (0x0600_0011, vec![(Token::new(0x0600_0051), a)]),
            (
                0x0600_0012,
                vec![(Token::new(0x0600_0052), a), (Token::new(0x0600_0060), b)],
            ),
        ]
        .into_iter()
        .collect();
        let extents = [(a, extent(0x50, 3)), (b, extent(0x60, 1))]
            .into_iter()
            .collect();
        let (resolved, unresolved) = solve(&candidates, &extents, None);
        assert!(unresolved.is_empty(), "{unresolved:x?}");
        assert_eq!(resolved.get(&0x0600_0012), Some(&Token::new(0x0600_0052)));
    }

    #[test]
    fn no_type_held_input_rows_past_the_dummies() {
        // Row 0x30 fits type B's only method (B then held input row 0x30) and type C's first of
        // twenty (C then held rows 0x30..=0x43). DotNetHook allocated its dummies from row 0x35,
        // past every input row, so C cannot have held rows up to 0x43.
        let b = Token::new(0x0200_0003);
        let c = Token::new(0x0200_0004);
        let candidates: BTreeMap<u32, Vec<(Token, Token)>> = [(
            0x0600_0030,
            vec![(Token::new(0x0600_0060), b), (Token::new(0x0600_0070), c)],
        )]
        .into_iter()
        .collect();
        let extents = [(b, extent(0x60, 1)), (c, extent(0x70, 20))]
            .into_iter()
            .collect();

        let (resolved, _) = solve(&candidates, &extents, Some(0x35));
        assert_eq!(resolved.get(&0x0600_0030), Some(&Token::new(0x0600_0060)));
        let (_, unresolved) = solve(&candidates, &extents, None);
        assert!(
            unresolved.contains(&0x0600_0030),
            "without the limit both fit"
        );
    }
}
