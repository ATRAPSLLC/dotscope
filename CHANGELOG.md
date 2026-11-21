# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **One work budget and one set of emulation limits.** `EngineConfig::budget` (an analyssa
  `WorkBudget`) bounds every pass, the scheduler and the analyses they read, replacing the
  per-pass and per-phase iteration counts (`with_budget` replaces `with_max_iterations`;
  `Budget`, `Exhaustion` and `WorkBudget` are re-exported from `analysis`).
  `EmulationConfig::limits` is the `EmulationLimits` every method's limits derive from
  (`ProcessBuilder::with_limits`), and `EngineConfig::unflattening` is the one
  `UnflattenConfig`.
- **Code generation is rebuilt around the order it emits in** (#288): operations are emitted
  in SSA order, a value moves to its use only where analyssa's `FoldForest` proves it
  unobservable, slots are shared by analyssa's `Gathering`, and phi copies are one parallel
  copy per edge. Every generated body is translation-validated (`compiler::validate_lift`); a
  refused one keeps its IL (`EventKind::CodegenRefused`).
- **Validators enforce only ECMA-335 rules and what the runtime refuses**, so validation no
  longer fails assemblies the runtime loads.
- **Every codec encodes back what it reads**: custom attribute values, marshalling
  descriptors, declarative security, method bodies, signatures, sequence points and custom
  debug information follow the ECMA-335 and Portable PDB grammars.
- Output is deterministic, and a failing load names the first failing row in token order.
  Every documentation example compiles, and examples run as doc tests. The docs build without
  a broken, ambiguous or redundant link, private items included (`cargo doc
  --document-private-items` is what CI checks).
- **BREAKING**, assembly: `FlowType` gains `CallIndirect` (`calli`) and `MethodJump`
  (`jmp`, which leaves the method), both `Call` before, so no consumer reads the opcode byte
  to tell them apart (`as_str`: `"call_indirect"`, `"method_jump"`).
  `Instruction::fall_through` and `FlowType::falls_through` state where control continues
  when an instruction does not branch, a `switch`'s default among them.
- **BREAKING**, loading: `CilObject::from_view` and `from_view_with_validation` return a
  `ViewLoadError` holding the error and the view, so the raw tables of an assembly the
  semantic load refuses stay readable without parsing it again; it converts into `Error`
  for `?`.
- **BREAKING**, metadata: a type's `FieldList`, `PropertyList`, `EventList` and `modifiers`
  are `LazyList`s, allocated on first push (iterate and `get` as before; no `[i]`), and a
  strong name's key (`Identity::PubKey`, `EcmaKey`) is an `Arc<[u8]>`. Loading the 1017
  corpus assemblies takes 25% less time, peaks a third lower in memory and allocates 36%
  fewer times: a method body no other method names is no longer held twice while loading,
  decoded blocks keep no growth room and are found without a map, and a type's empty lists,
  its source, a leaf signature type and a signature's validation allocate nothing.
- **BREAKING**, analysis: a call is one `SsaOp::Call` holding `CallData` and its `Callee`
  (read through `SsaOpCilExt::method_call`), CIL prefixes are stated on the operation they
  prefix (`CilPrefix`), and evaluators take a `Machine` instead of a `PointerSize`. A float
  constant is `ConstValue::Float(FloatBits)`, `EmValue` converts from a `ConstValue` with
  `TryFrom`, and `SsaCodeGenerator::compile` is all or nothing (`generate_with_assembly` is
  removed).
- **BREAKING**, metadata: custom attribute values hold `Option` for null, a `Boxed` argument
  and `FieldOrPropType`; `MarshallingInfo` is one native type; `SecurityAction` and
  `SecurityPermissionFlags` take the runtime's values and permissions hold named arguments;
  `MethodBody` keeps its `exception_format`; `CustomDebugInfo` is decoded by kind;
  `SignatureMethod` gains `unmanaged` and its calling convention;
  `TypeSignature::ModifiedRequired`/`ModifiedOptional` hold the type their modifiers prefix
  (a modifier inside a type was parsed as the whole type, misreading the rest of the
  signature); signed compressed integers
  follow ECMA-335 and the compressed writers return `Result`. Names read from `#Strings`
  (types, methods, parameters and the named rows, cultures, P/Invoke import names) are
  `SharedStr`, a `Document`'s name is a `DocumentName` and its hash `SharedBytes`.
  `CilType::fullname()` returns a `FullName` (displays and compares as the joined name).
  The name getters return the shared values rather than copies (`CilTypeRef::name`,
  `CilTypeReference::name`/`fullname`, `MethodRef::name`, `Method::declaring_type_fullname`,
  `CilObject::resolve_method_name`), as do `AssemblyIdentity` (name, culture), DLL
  dependencies, exported functions and `Import::fullname`.
- **BREAKING**, loading and writing: a coded index whose tag names no table reads as null
  (`TableInfo::decode_coded_index` returns `Option`); a branch operand is
  `Operand::Target(rva)`; attached lists, `Property::fn_other`, `Event::fn_on_other` and
  `security` among them, are `RowList`s; `Identity::Token` is in .NET's byte order;
  `Method::varargs` is removed; `Resources` is keyed by token; the raw `to_owned` of TypeDef,
  MethodDef, EventMap, PropertyMap and LocalScope rows take the table's `MemberRanges`. A
  reference to a deleted row fails the write with `Error::DanglingReference` (or is null under
  `DanglingPolicy::Null`) instead of moving to the next row.

### Added

- Portable PDB: every load reads the PDB the image embeds or its own debug tables,
  `CilObject::pdb()` gives every table with queries, and `with_pdb` / `with_pdb_bytes` attach
  a standalone `.pdb`.
- `.resources` values of user types are kept (`ResourceType::Serialized`) and read as
  MS-NRBF (`resources::nrbf`); compiled XAML reads as a BAML document (`resources::baml`).
- Metadata queries: `Root::stream` and `unread_streams`, `Param::from_signature`,
  `type_tokens` on signatures, `TokenResolver::generic_definition`,
  `CilAssembly::find_corelib_type`, `CilObject::fields` and `custom_attributes`,
  `CilType::enum_underlying`, and the runs of the list columns (`MemberRanges`,
  `TablesHeader::member_ranges` and `member_rids`), `PdbStream::to_bytes`, and what
  implements a method and where its first instruction is (`Method::code_kind`,
  `MethodCodeKind`, `Method::code_rva`).
- Members of public types that were crate-internal, now public: `CilObject::from_project`
  with `project::ProjectContext`, `CilAssemblyView::load_with_validation`,
  `assembly::decode_method` (beside `DecodedBodies`), `CustomAttributeParser`,
  `PortablePdb::new`, `pdb::PDB_TABLES`, `TokenResolver::new`, `CilType::mark_value_type`,
  the signatures' `for_each_type_token_mut`, and the fields of `HeapRef` and `NativeReader`.
  Internal items take their reach from private modules, not restricted visibility. Every
  type public API takes, returns or holds can be imported, re-exported beside the API that
  hands it out (`LazyList`, `RowList`, `TextHash`, `AssemblyChanges`, `WorkQueue`,
  `ExecutionStats`, ...), and `deny(unnameable_types)` keeps it so. Public docs link only
  public items: `debug_type` (the kinds `DebugDirectoryEntry::kind` takes),
  `resources::baml::known`, `StateMachineState` and `EmulationContext::with_call_signature`
  are public.
- `dotscope::io` (the binary codecs), SSA forms for `arglist`, `mkrefany`, `refanyval` and
  `refanytype`, and the hidden, unstable `testkit` feature.
- Deobfuscation: `bitmono.tokens`, `bitmono.locals`, `netreactor.emptyresource`, a metadata
  repair registry, and exports of `repair_pe`, unflattening and the conflict resolution types.

### Removed

- Configuration nothing read: `DecryptorHeuristics`, `UnflatteningThresholds`,
  `detection_threshold`, `verify_semantics` and `resolution_strategies`.
- `analysis::conv_op_for_target` and the `skip-expensive-tests` feature.
- `Method::is_forwarded_pinvoke`, which tested a range bound as a flag and was always false
  (`Method::is_forward_ref` is the `ForwardRef` test).
- **BREAKING**, deobfuscation: the LLM renamer. The `smart-rename` feature (dotscope and
  dotscope-cli), `SmartRenameConfig`, `CleanupConfig::smart_rename` and the CLI's
  `--rename-ai` are gone, and with them the `mistralrs` and `tokio` dependencies. Cleanup
  renames obfuscated identifiers to sequential names as before.
- **BREAKING**, metadata: the table loaders (`metadata::tables::AssemblyLoader` and the
  others), unit structs implementing a private trait, are no longer public.

### Fixed

#### Loading and metadata

- Images load as the CLR loads them: stream directories, the `#~` ExtraData word, `#JTD`
  tables, any metadata version text, zero-length heaps (Mono's `ilasm`) and ConfuserEx's
  "invalid metadata" (#289). Bytes at an RVA are read through one section map as the runtimes
  map them.
- Signatures parse in one pass bounded by their bytes, without invented caps; array
  signatures no longer misparse what follows them and refuse ranks no array has. Walkers see
  through a modified type: token collection and renumbering, stack and byte sizes, flavors,
  SSA types and emulation's generic substitution (which now also substitutes inside
  pointers, general arrays, function pointers and varargs).
- Custom attribute arguments are read by the constructor's signature and enums by their
  underlying type, so 72 Mono framework assemblies load.
- Type flavors, nested generic instances and core library types no longer depend on loader
  timing; a project's registries list only their own types; StateMachineMethod rows,
  sequence points and Portable PDB data load as the compilers write them.
- Native imports and exports are walked entry by entry as the Windows loader walks them,
  bounded by the file. DLL names are compared ignoring case, as the loader compares them:
  `get_all_dll_names` and `get_all_dll_dependencies` list a DLL once, in a stable order.
- A row's name shares one copy of its `#Strings` run, and a document's name and hash view one
  copy of `#Blob`: many rows naming one long string, or a document name repeating one long
  part, no longer cost rows times length in memory and time (`Strings::get_shared`,
  `Blob::get_shared`, `Blob::document_name`). Full names are not joined while loading: a
  `FullName` links to its enclosing type's and is indexed by a hash of its text, and a nested
  type's name follows an enclosing type nested after it was first read.
- A method's code type is compared as the two-bit enumeration it is: `is_code_il` held for
  every method, and `is_code_native` and `is_code_opt_il` for a runtime-implemented one, so
  `query().il()` matched every method and the native-code passes and the emulator took a
  runtime method for native code.
- List columns (fields, methods, parameters, events, properties and a PDB scope's locals) are
  read once per table into runs clamped to their table and kept from overlapping, so a
  hostile column no longer costs billions of iterations or quadratic memory; loading,
  cleanup, renaming and repairs share them and follow the Ptr tables of `#-` streams.

#### Project loading

- A panic while loading an assembly no longer hangs `ProjectLoader::build`, and a dependency
  that fails or panics is left out (reported in `failed_loads` with its own error) while the
  others load without it; the primary failing fails the build. `strict_mode` fails on a
  dependency that is missing or fails to load, and `missing_dependencies` lists
  only names that were not found.
- Dependency names from AssemblyRef rows must be simple file names, and a candidate must
  resolve inside its search directory (no absolute, `..`, UNC or symlinked escape). Each
  file is read once and each name probed once; `ProjectLoader::max_assemblies` bounds a
  build.
- A TypeRef binds in the assembly its AssemblyRef names, not to the first type of that name
  in any loaded assembly. `CilProject` is updated atomically and lists and searches its
  assemblies in identity order (`AssemblyIdentity` is `Ord`); `clear` resets the primary.

#### ILAsm output

- Quoted strings and names share one escaper: string constants, P/Invoke modules and entry
  points, cultures and assembly, module, file and resource names were written unescaped, a
  quote ending them early, and a user string that is not valid UTF-16 goes out as
  `bytearray (...)` instead of decoded lossily. Floats are written as the shortest decimal
  that reads back as the same value, and an infinity, a NaN or negative zero as its bits
  (`inf`, `NaN` and `-0` are no ILAsm, and a large value had hundreds of digits).
- A general array is written with its bounds (`[0...,0...]`, `[1...5]`; it was `[rank]`, which
  ILAsm reads as a single-dimensional array of that size), and `.locals` comes from the parsed
  signature, `T& pinned` rather than `T pinned&`, even when its types do not resolve. A local
  signature token is read only as a StandAloneSig token (`MethodBody::local_var_sig_rid`):
  the loader, cleanup, SSA typing and the formatter masked any token to a row.

#### Validation

- Validators accept what the runtime loads (every Mono 4.8 and .NET 10 runtime assembly loads
  as one project), and rules that never fired check what they name. A type implementing a
  defined non-interface is refused by its flags, not by its name.

#### Write path and cleanup

- An assembly written back unchanged holds what it held: method bodies past 8 MB, fat
  headers, shared heap tails, user strings as read, the debug directory, PDB blob columns,
  unassigned coded index tags, every exception clause of a rewritten body (one outside its
  code included), and the native import and export tables, a function imported twice from
  one DLL included.
- A write that renumbers rows or replaces bodies regenerates the Portable PDB the image
  embeds for the rows it now describes, and the CodeView and checksum entries name the new
  PDB; a standalone PDB stays named only while the output still matches it (#291). Debug
  tables an assembly holds in its own metadata follow the methods a write deletes, replaces
  the bodies of and adds the same way.
- Heap placeholders no longer pass for offsets (each assembly counts its own change ids), an
  index too wide for its column is refused, the output grows past its estimate, and replaced
  bodies' `ldstr` operands follow a moved user string heap. A write looks each placeholder
  up in an index it builds for the write instead of scanning every change, and
  `string_get_or_add` finds a string already appended through a content index: both scans
  made writing quadratic in the rows and strings added (8000 new types: about 9x fewer
  instructions). Entries added after a heap was replaced are named where the write puts them
  (offsets and index widths came from the replaced heap). Renaming a string no longer
  compacts the heaps, which failed the write of in-image debug tables
  (`AssemblyChanges::referenced_string_offsets`, which it filled and nothing read, is
  removed); cleanup's compaction keeps the blobs other blobs name. The tails tables name
  inside a renamed string are written in offset order, its terminator stays the empty string,
  the tails inside a duplicate string follow it to the copy it merges into, and finding them
  is a binary search instead of a scan per entry (20000 strings: about 125x fewer
  instructions).
- Cleanup keeps what surviving metadata names and renumbers only signature blobs;
  `add_cleanup` narrows earlier requests instead of resetting them; table operations are
  ordered by a logical timestamp; builders start their lists at the next row. `MethodBuilder`
  declares P/Invoke, internal-call and runtime-implemented methods and refuses a bodyless
  method of any other kind, as ECMA-335 §II.22.26 does. It decides
  which types go before deleting any member, so a requested type that surviving code still
  names stays whole instead of as an emptied shell; deleting a type deletes what is nested
  in it at every depth; and a protected or surviving nested type keeps its enclosing chain,
  which empty-type removal no longer deletes.
- `.resources` streams are written as `ResourceWriter` writes them, a public key token prints
  in .NET's order, and `repair_pe` repairs any directory count past 16.

#### Analysis and code generation

- Every corpus method lifts to SSA the verifier accepts: arithmetic is typed by ECMA-335's
  numeric table, an enum computes as its underlying integer, every conversion is restated for
  its operand's type, and `.locals init` locals read zero. The lift parses a method's local
  signature and resolves the runtime handle types once per method instead of at every access
  (3-6% fewer instructions lifting whole assemblies). Compacting a method's locals moves
  their declared types with them; code generation had paired each local after a dropped one
  with the type declared for the local before it. Code the runtime refuses (ECMA-335
  III.1.7.5) no longer lifts: control falling off the end, a branch to no instruction or into
  an operand, and a join reached at two stack depths are errors rather than SSA the verifier
  or code generation rejects. The decoder ends a block at `jmp`, which leaves the method,
  instead of giving it a fall-through.
- Constant folding respects width, kind and NaN, pure-call folding needs a pure callee, and
  a chain of conversions is shortened only where the inner one keeps the value (an `int16`
  through `conv.u2` does not).
  The `z3` solver builds against analyssa's typed operations and states every operation as
  the value it computes, leaving what the target decides unconstrained.
- The x86 lift of native stubs is exact or refuses, so a stub it cannot follow stays native
  instead of becoming CIL that computes something else. Conditions after every flag
  producer follow the processor's flags (a jump after an addition compared the sum with
  itself, and signed and unsigned conditions compared the wrong values), 8- and 16-bit
  registers are their bits of the full register, flags survive the instructions that do not
  touch them, MUL and DIV use EDX, MOVZX/MOVSX/CWDE extend, shifts mask their count, rotates
  rotate, blocks fall through and each has its own zero; bit scans, BTS/BTR/BTC, CBW, CWD,
  the one-operand IMUL, an ADC with an unknown carry, 64-bit code and SSA that does not
  verify are refused. The linear decode no longer stops at a RET that a jump passes.
- Exception clauses come nested first in a stable order, and generated code handles `calli`,
  typed element access and values leaving a `try` through its `finally`. A filter's
  `endfilter` is laid out as its last instruction, as ECMA-335 requires (377 corpus methods
  kept their original IL because the fall-through order put filter code after it).
- Call graphs and class hierarchy analysis find every override and implementation, end on
  inheritance cycles and order callees first.
- A `callvirt` naming a BCL virtual or interface method by its MemberRef runs the receiver's
  override (by MethodImpl, else by name and signature) before any hook: a user `ToString`,
  `Dispose` or `Stream.Read` runs instead of the BCL method's hook.
- The emulator charges native work to its budget, reads heap objects in place and finds a
  field's declaring type through the field itself, as it does a method's. Heap objects and
  static values sit behind `Arc`: the first write after a fork copies the object it writes
  instead of every object beside it in the persistent map, and hooks read objects shared
  (`ManagedHeap::get_shared`) instead of copying them (`Array.get_Length` copied the array).
  An array index is an integer, as ECMA-335 states: an object is no longer searched for one
  (a boxed integer or the first integer field stood in for the index the program lacked).
  `ldfld` and `stfld` through a pointer to an object's field (`ldflda`) read and write the
  struct the field holds; they went to the object holding the field.
  A hook's result is checked against the signature of the method it stands for (a value
  for a void method stayed on the caller's stack, a missing one let the caller pop what lay
  below). `newobj` pushes what a constructor hook constructs, the object it initialized or
  the value it returns (the new objects of the HMAC and `RNGCryptoServiceProvider`
  constructors were dropped, and `ComputeHash` hashed the bare object with an empty key; it
  now refuses an object no HMAC constructor initialized), and a `DateTime` constructed on a
  local stores its ticks there instead of on the caller's stack; its properties read through
  a pointer to it. `DateTime.Now` of a deterministic build (a `Repro` debug entry) is not its
  header stamp, which is a hash, and the .NET Reactor trial checks are bypassed in every
  emulation the pipeline runs, as they were for NecroBit (the decrypters ran into them once
  `DateTime` values were real).
  A delegate's `Invoke` through a MemberRef (`Action`, `Func` and every delegate type of
  another assembly) runs the delegate's method; it was an unhooked call answered with a
  symbolic value. A delegate bound to a target passes it as the first argument (an instance
  method took its `this` from the caller's stack), and a multicast delegate runs each later
  entry as its `Invoke` again at the call site, so it returns to the caller with its stack
  and pending `leave` (it returned into the entry before it). A type's initializer no longer marks its
  base type initialized without running the base's. An unhooked P/Invoke leaves its
  arguments in order, and a bodyless void method returns nothing instead of a symbolic value.
  A method of an assembly loaded with `Assembly.Load` runs in that assembly, and so do the
  methods it calls by its own tokens; a call into it is resolved there (it was resolved again
  in the calling assembly, and its callees ran against the main assembly's metadata). The
  deobfuscation template maps the original PE once, under aliases for its file and module
  names, instead of a copy per name forked with every process. It runs the 18
  single-byte `conv.ovf.*` opcodes as ECMA-335 numbers them, which it had only as mislabelled
  two-byte copies, and `no.` decodes, lifts and runs. Float `bge`/`ble` and their `.un`
  forms follow ECMA-335 on NaN, and a string built from characters takes them as `char` or
  `int32` and refuses what the runtime refuses instead of answering an empty string. `Math.Round`
  and `MathF.Round` round a midpoint to even unless a `MidpointRounding` says otherwise.
  Strings are measured and indexed in UTF-16 code units, as .NET does: `Length` and
  `Chars[i]` answer in O(1) (they counted characters, so a decryption loop over a string was
  quadratic, and miscounted any character outside the Basic Multilingual Plane), and
  `Substring`, `ToCharArray`, `IndexOf` and padding take those indices, throwing for a range
  outside the string or a null receiver as the runtime does; `IndexOf` answered a UTF-8 byte
  offset and ignored its start, `ToCharArray(start, length)` its range. Hooks see the
  parameter and return types of a framework method called through a MemberRef.
  Symmetric transforms implement all five padding modes and throw `CryptographicException`
  for a wrong key size, partial blocks or padding that does not check out (decrypting with
  the wrong key) instead of handing the input back as the output; a padding decryptor holds
  its last block back from `TransformBlock`, and a transform returns to its initial IV after
  `TransformFinalBlock`. A `callvirt` through a base method reaches the hook of the
  receiver's runtime type first, so a CryptoStream or DeflateStream read or written through
  `Stream::Read`/`Write` is no longer treated as a plain stream that reads nothing and drops
  writes. A CryptoStream closed or disposed without `FlushFinalBlock` writes its final
  block, and a second `FlushFinalBlock` throws. Corrupt compressed data throws
  `InvalidDataException`, a malformed RSA XML key `CryptographicException`, and transform,
  stream, reader and writer hooks check buffer arguments as the runtime does, throwing its
  argument exceptions instead of clamping or reading nothing.

#### Deobfuscation

- Control flow unflattening repairs each rewired edge through the values it disturbs instead
  of spilling cross-block values to locals and rebuilding the method.
- Passes remove only what nothing reads, and a failing pass rolls its method back
  (`EventKind::PassFailed`). Decryptors receive values earlier decryptions produced, and
  `process_ssa` runs with the engine's configuration. A byte transform that failed or found
  nothing to do, or whose technique another detected one supersedes, no longer counts as
  pending and makes the whole pipeline run again, up to the iteration limit; and runs sharing
  an engine no longer share one run's technique order. A state-machine decryptor call with no
  seed found is not decrypted (seed 0 stood in, giving a wrong value), the state machine stays
  while a call site that failed still reads it, the direct mode leaves those call sites to it
  (a second failure was recorded for each), decrypted values are cached per generic
  instantiation (`Get<B>(42)` answered `Get<A>(42)`'s), and opaque-field folding takes only
  chains rooted in a detected field through fields never stored at runtime (it froze any
  static the warmup had set).
- BitMono tokens resolve by signature, ConfuserEx output passes validation, and .NET Reactor
  samples get their resources and `typeof`s back. NecroBit reads each restored body through a
  window the size of the body instead of the rest of the image, and checks a heap array for
  its blob from the header before copying it (both copied once per stub or array).

#### Tests

- The suite fails where it used to pass without testing: every sample is a manifest fixture,
  every corpus assembly must load and every method lift, and no verdict depends on machine
  load. Tests run in tiers; packer samples are checked by what they print under Mono, and the
  System.Reflection.Metadata oracle compares every corpus assembly. Fuzzing runs locally,
  with every failing input replayed as a regression test; benchmarks measure time and memory.
  Every packer sample is deobfuscated twice, in pools of one and eight threads, and the
  outputs must be byte-identical; codegen tests name the instructions they expect instead of
  accepting any of several.

## [0.9.1] - 2026-09-05

A dependency release, and the defects that adopting the dependency exposed.
analyssa 0.6.0 reshapes how an exception clause is represented and takes away
the CFG relations `SsaFunction` used to answer itself — which forced every
analysis to say which graph it wanted, and three of them turned out to have been
reading one that contains no handlers. The rest of the set shares that shape: an
exception clause read through fields that could not say what the clause meant.

### Fixed

- **Liveness ran over a graph in which no handler is reachable.** The local
  coalescer built its dataflow CFG from terminator edges alone, and nothing
  branches to a handler entry — the runtime dispatches into it. A variable live
  only across a protected region therefore came back dead, and the coalescer was
  free to give its slot to something else. It now solves over the
  exception-aware view; the extra edges only widen liveness, which is a
  may-analysis, so nothing that was correct becomes wrong.

- **SCCP folded values defined in handlers as constants nobody wrote.** The same
  graph, the same reason, the opposite direction: constant propagation is rooted
  at the entry and walks forward, so a handler block was simply never visited
  and every value defined in one stayed at `Top` — the lattice element meaning
  "no definition has reached this yet", which the fold reads as a constant. Both
  SCCP rounds now run over the exception-aware view.

- **A filter clause's handler body resolved to its filter expression.** The
  decoder marks the filter's entry block and the handler body's entry block with
  the same handler index, and the filter is laid out first, so the search that
  took the first match answered with the filter block for every `catch … when`
  clause — a wrong `handler_offset` in the regenerated exception table. The
  filter is now resolved first and excluded from the handler's own search.

- **Full inlining remapped only an operation's primary destination.** An
  operation defining a secondary or flag output would have carried the callee's
  variable id for it into the caller, where it means something else. Latent for
  a CIL front-end, whose operations define one variable each, and repaired
  rather than left to a future one: every definition the operand walk reports is
  now remapped. That disagreement is why analyssa removed the
  single-destination setter this used.

- **One malformed PE resource discarded an assembly's entire metadata.** goblin
  walks the resource directory in strict mode by default, so a single bad
  `ResourceString` in a `VS_VERSIONINFO` block aborted the whole PE parse and
  took every byte of CIL metadata with it. Nothing in dotscope reads that
  directory — a .NET assembly's own resources live in the managed metadata — so
  it is no longer parsed.

- **CFF dispatcher detection counted a self-loop by hand.** It compensated for a
  predecessor relation that dropped self-edges by scanning the block's
  instructions for one. The relation it now asks reports a self-edge like any
  other, so the compensation is gone and predecessor counts agree with what phi
  validation sees.

### Changed

- **BREAKING**: **An exception clause is three optional block ranges, not five
  loose block indices.** `SsaExceptionHandler` carries `protected_range`,
  `handler_range` and `filter_range` — each a half-open `BlockRange` or nothing —
  in place of `try_start_block`, `try_end_block`, `handler_start_block`,
  `handler_end_block` and `filter_start_block`. A part can no longer be half of
  itself: a region that began somewhere and ended nowhere was a state the old
  five fields could hold and no check could refuse.

  A CIL filter's extent is now recorded rather than inferred. It is
  `[filter_offset, handler_offset)` — the blocks between the filter's entry and
  the handler's — so a filter clause finally says where its expression is
  instead of leaving every reader to guess it from the neighbouring parts.

  `BlockRange`, `ClausePart`, `ClauseLayout`, `LaidOutHandler`, `HandlerKind`,
  `ExceptionBlocks` and `ExceptionTableError` are re-exported from
  `dotscope::analysis`, so a caller holding a dotscope exception handler has the
  vocabulary it answers in without naming analyssa.

- **BREAKING**: **`SsaBlock::terminator_op` is `SsaBlock::control_terminator`.**
  The old name was positional — the block's last instruction, whatever it was —
  while every call site was asking a control-flow question. The rename is
  analyssa's; dotscope's call sites now ask the control question, so a block
  whose last instruction is not a terminator contributes no edges rather than
  edges leaving from an instruction control cannot reach.

- **BREAKING**: **`SsaFunction` no longer answers predecessor or successor
  questions.** `block_predecessors` and `block_successors` are gone;
  `SsaCfg::from_ssa` is the terminator-derived relation and `EhCfg::from_ssa`
  the exception-aware one, and which one an analysis needs is now a decision it
  has to state.

- **BREAKING**: **`SsaOp::Break` carries a `BreakpointOp`.** CIL `break` is
  `SsaOp::Break(BreakpointOp::Breakpoint)`. `BreakpointOp` is re-exported from
  `dotscope::analysis`.

- **BREAKING**: **`ConstValue` gained a `Symbol` variant, so exhaustive matches
  on it need one more arm.** CIL has no symbol space — every entity is named by
  a metadata token that the type, method and field references already carry — so
  `CilTarget::SymbolRef` is an uninhabited type and the arm is unreachable by
  construction.

- **`Target::handler_kind` replaces `Target::is_filter_handler`.** `CilTarget`
  classifies through the existing `ExceptionHandlerFlags::kind`, so the
  ECMA-335 §II.25.4.6 bit classification has one definition in the crate rather
  than two that can disagree.

- **UTF-16 and UTF-32 decoding takes the chunks as arrays.** Seven sites cut a
  byte slice into fixed-width units by hand: six paired `chunks_exact(N)` with a
  fallible conversion back to `[u8; N]`, and one indexed the chunk byte by byte.
  Each carried a fallback for a case that cannot arise — a dropped code unit, a
  zero, an error return. `as_chunks` yields the arrays themselves, so the
  fallbacks and the bounds checks are gone with them.

### Dependencies

- `analyssa` 0.5.0 → 0.6.0
- `quick-xml` 0.41.0 → 0.42.0. Element names and attribute keys are `&str`
  rather than `&[u8]`, so `PermissionSet`'s XML reader compares them directly
  instead of decoding each one and reporting a UTF-8 error the parser has
  already ruled out.
- `z3` 0.20.2 → 0.21.0

## [0.9.0] - 2026-08-15

A security and correctness release. dotscope parses, emulates and rewrites
hostile input, and this release closes the gap between what the resource limits
claimed to enforce and what they actually did, along with a set of
miscompilations in the SSA back end and layout defects in the PE writer.

### Security

- **Resource limits are enforced before the work happens, not after.** The
  managed-heap ceiling was checked once the object was already materialised;
  unmanaged allocation (`localloc`, `AllocHGlobal`, `AllocCoTaskMem`,
  `VirtualAlloc`) had no budget at all, and `max_unmanaged_bytes` and
  `max_heap_objects` were declared but never read. Allocation
  now runs through a reservation that must succeed first, in-place mutation is
  accounted, and forks inherit the ceiling instead of escaping it.
- **Unbounded and quadratic work on attacker input.** Fixed in the inheritance
  walker (a cyclic `extends` graph caused an uncatchable native stack overflow),
  the x86 traversal (O(n²) to end of file), method-body decoding (disassembled
  past the declared `code_size`), exception-handler association (O(H²·B) at load
  time), DEFLATE/GZIP/LZMA expansion, and the signature parser (a blob could
  build a ~61 000-deep type whose recursive drop overflowed the stack).
- **Argument validation across the BCL hooks.** Negative or oversized lengths
  reaching `Marshal.Copy`, `Stream.SetLength`, `StringBuilder.set_Length`,
  `String.PadLeft`/`PadRight`, the `BinaryReader` readers and the PBKDF2
  constructors reserved `usize::MAX`, ran multi-billion-iteration loops, or
  drove a ~4.3-billion-round KDF. They now reject the value and raise the .NET
  exception.
- **Emulator forks were not isolated.** "Isolated" forks shared one mutable
  runtime state, AppDomain and synthetic-method map while running concurrently.
  `Assembly.Load(byte[])` is now bounded by `max_loaded_assemblies` and
  `max_loaded_assembly_bytes`, and runtime-loaded assemblies parse with minimal
  validation rather than the full pipeline over hostile bytes.
- **Memory protection flags are enforced** on read and write, faulting through a
  new catchable `AccessViolationException`, and region mappings are overlap-checked.
- `deny(unsafe_code)` is enabled. One `unsafe` block remains, for the writer's
  output mapping, with a targeted allow and a SAFETY note.
- `SECURITY.md` now states the supported version, the real `EmulationLimits`
  defaults and what is actually run. The previous text listed DoS protections as
  "ToDo" and claimed Valgrind testing that does not exist.

### Fixed

- **Malformed table rows silently truncated a table.** The row iterators
  reported a parse failure as end-of-iteration, and because the writer rebuilds
  tables by iterating them, an unreadable row became *missing output* rather
  than an error. Iterators now yield `Result`, `get` returns
  `Result<Option<T>>`, and `MetadataTable::new` validates and truncates to the
  declared extent.
- **`MethodPtr`, `EventPtr` and `PropertyPtr` tokens used the wrong table id**,
  so any assembly carrying a `*Ptr` table lost its method-bearing types.
- **Three back-end miscompilations.** Full inlining placed the return-value copy
  before the instruction defining it; switch and conditional-branch phi
  trampolines fell through into the next edge's copies. Critical edges are now
  split into real blocks by a dedicated out-of-SSA pass.
- **Handler SSA used a "last block wins" snapshot** of try-scope definitions
  because the CIL CFG carried no exception edges. Real EH edges make handler
  entries ordinary join points.
- **Linear-scan allocation computed live intervals with no liveness solve**, so
  a value live across a back edge could have its slot clobbered.
- **Four exception-unwind defects**: the caller's `finally` ran against the
  grandparent frame, queued `finally` blocks were never drained once a catch was
  selected, a `leave` out of nested `finally`s spun on `endfinally`, and a filter
  returning zero terminated emulation instead of resuming the handler search.
  A CLR exception raised by an instruction the controller completes (`unbox` of
  null or of another type, a failed `castclass`, `initobj` through null) is thrown at that
  instruction and reaches its handlers; it ended the run as an emulation error.
- **PE writer layout.** Heap offsets were computed twice from different inputs,
  so offsets baked into tables and IL disagreed with where data was written;
  heap index widths were inherited from the input and truncated above 0xFFFF;
  section `SizeOfRawData` came from the virtual extent; and the input's
  certificate directory offset was applied to the output, zeroing live `.text`
  before the checksum was computed over the damage. `Output` now writes to a
  temp file and renames.
- **Cleanup deleted live metadata**: TypeRef liveness ignored `ResolutionScope`,
  and the opaque-field pass folded any static-to-instance load and deleted the
  owning type with no immutability precondition.
- Byte-offset slicing of string literals panicked on multi-byte UTF-8;
  `clippy::string_slice` is now denied, which surfaced ten genuine sites.
- The fuzz crash-corpus regression test passed on any checkout without the
  corpus, and CI ran `cargo test --lib`, so the integration tests never executed
  on Windows or macOS. Both are fixed, and the 72 crash artifacts are committed.
- **An array signature's rank was never bounded**, and it was the only ceiling on
  the lower-bound count that follows it, so a declared rank of 0x400000 made that
  check permissive rather than protective and the dimension list grew to the
  declared count before any read could run out of input. This accounted for every
  out-of-memory artifact found by fuzzing.
- **Type-name validation rejected legitimate compiler-generated names.** It
  matched a hand-written list of prefixes, so `<Module>{GUID}` failed on untouched
  input as well as on rewritten output; the closed angle bracket the C# compiler
  guarantees is the real invariant. Validation failures also reported only how
  many validators failed, discarding the messages saying why.
- **Cleanup deleted enclosing types whose nested types were still referenced**,
  leaving a NestedClass row pointing at a TypeDef that no longer existed.
  Reachability now walks the nesting relation to a fixed point.
- **Reachability used the SSA call graph alone**, so every method without SSA
  looked unreachable and the live set was under-approximated. SSA edges are now
  preferred where they exist and the static graph fills in where they do not.
- **Opaque static fields were only folded when every write came from a `.cctor`.**
  Obfuscators route initialization through helpers, so those fields stayed opaque
  and their predicates survived. A write site now counts when every caller of the
  writing method is itself initialization-only; a method with no known caller is
  not admitted. .NET Reactor string samples go from 223 decryption failures to
  none.
- **Parameters removed with their method left dangling references behind them.**
  `Constant`, `FieldMarshal` and `CustomAttribute` rows name a parameter through
  a coded index and are dropped by asking whether their parent was deleted, but a
  parameter discarded along with its method never entered that record — what had
  been deleted was the method. The rows outlived the parameters they named and
  the output failed raw validation with an out-of-range `Param` RID. Removed
  parameters are now cascaded to all three tables.
- **.NET Reactor NecroBit recovered nothing from full-protection binaries.**
  Every encrypted body was lost on both such samples — 0 of 59 and 0 of 562 —
  while necrobit-only binaries were unaffected. The cause was not in the
  decryption: a protection that resolves `VirtualProtect` through
  `LoadLibrary`/`GetProcAddress` and calls it through a delegate never reached
  the hook that implements it, so the pages holding the method bodies stayed
  read-only and the write-back faulted on the first body. Both samples now
  restore every stub and validate.
- **A native function resolved at runtime never reached its hook.** Hook matching
  required a declared P/Invoke, so any function obtained through `GetProcAddress`
  and invoked through `Marshal.GetDelegateForFunctionPointer` bypassed it — the
  delegate path answered from a small table of hardcoded return values instead,
  reporting success without performing the call's effect. Such calls now carry
  their arguments and dispatch through the ordinary hook path. `LoadLibrary`
  hands out a distinct handle per module so the resolved function can be matched
  against the library it came from.
- **A refused write was retried as a fresh mapping.** `Marshal`'s write path
  treated "mapped, but not writable" the same as "not mapped" and tried to
  materialise a window at the enclosing 64KB boundary. For an address inside a
  loaded image that is the image base, so the attempt collided with the image and
  reported an overlap — turning a recoverable permission error into a fatal one
  that named the wrong cause. The two cases are now distinguished.
- **A failed body-decryption transform caused cleanup to delete the code it
  could not decrypt.** A technique fills its cleanup request during detection,
  before it knows whether the transform those deletions depend on will run. When
  a byte transform fails, the bodies it was meant to restore stay encrypted;
  such a method contributes no call edges, so everything it references reads as
  unreachable and the type-level sweep removes it. One .NET Reactor sample fell
  from 1181 methods to 87. Techniques now report what they could not restore
  (`Technique::unrecovered_methods`), cleanup protects those methods, withholds
  the failed technique's own request, and skips unreferenced-type removal for the
  run — the call graph cannot tell unreachable from undecrypted. The same sample
  now keeps 946 methods and validates.
- **Unflattening could emit a function that failed SSA validation**, which
  aborted deobfuscation for the whole assembly rather than the method. Rewiring a
  dispatcher edge can skip a definition that a surviving block still reads; the
  guards that prevent this have gaps, so the rebuilt form is now checked and a
  method that cannot be rewired safely is left flattened.

### Performance

- `EmValue` drops from 200 to 104 bytes on x86-64 by boxing `CilFlavor::FnPtr`,
  halving every value in the interpreter. Pinned by a static assertion.
- `Method`, `CilType` and `Param` no longer eagerly allocate 8–11 `Arc<boxcar::Vec<_>>`
  each; `LazyList<T>` defers to first use.
- Type resolution: `get_by_fullname` no longer falls back to a linear scan of
  every registered type (reachable once per custom-attribute argument), and
  `fullname()` returns `Arc<str>` instead of allocating a fresh `String` at every
  call site.
- Declaring-type lookups are indexed rather than brute-force scans over every
  type and member — they sat on the emulator's hottest paths.
- Table loaders no longer take a shared `Mutex` once per row inside the rayon
  loop; an inherent `try_for_each` had been shadowing rayon's in every loader.
- Handler SSA no longer rebuilds a version-stack snapshot per exception
  successor per block, and unmanaged access is a `BTreeMap` lookup rather than a
  linear region scan that allocated a `Vec` for a 1–8 byte read.

### Changed

- **BREAKING**: **CFF unflattening resolves dispatcher edges from SSA instead of
  enumerating execution paths.** The old tracer walked the method from entry and
  forked at every conditional, which is exponential in the number of branches and
  re-explored the whole method once per dispatcher. The state reaching a
  dispatcher is a phi whose operands are indexed by predecessor, so the value on
  each edge can simply be read; recovering it is linear in the number of edges.
  Encodings that derive each state from the previous one are resolved by a fixed
  point over states — one iteration per original block, not per path.

  On one .NET Reactor sample the tree cost 108.8 million nodes and 62 seconds
  across 40 dispatchers; the same work now takes 0.16. `reactor_full` drops from
  615 to 154 seconds, of which unflattening is 1.1. The tracer and the patch-plan
  reconstruction are deleted, roughly 3 400 lines net.

  Edges are only rewired when the answer is provable: the case index is obtained
  by evaluating the dispatcher's own switch operand rather than a reconstructed
  transform, arithmetic folds at the operand's width because state encodings rely
  on int32 wraparound, and a block is skippable only when everything it computes
  feeds the state machine and nothing else. An edge that cannot be resolved keeps
  routing through the dispatcher, so coverage degrades rather than correctness,
  and blocks holding a call, a store or a string are never removed on the strength
  of an analysis that is allowed to be incomplete.

  `unflatten` and `unflatten_with_dispatchers` no longer take a config or an
  assembly, `CffReconstructionPass::new` takes only the context, and the patch
  plan API is gone. `UnflattenConfig` and `UnflatteningThresholds` lose the knobs
  that drove path enumeration; the ones that remain are now actually applied by
  detection, which previously built a config and then ignored it.
- The workspace declares `rust-version = "1.95"`, and the minimal-features CI job
  is pinned to it — and extended with a default-feature workspace check — so the
  MSRV is verified rather than merely stated.
- **BREAKING**: `Error` is `#[non_exhaustive]` and derives `Clone`. The previous
  hand-written `Clone` rewrote most variants into `Error::Other(String)`,
  destroying the taxonomy for any caller that cloned.
- **BREAKING**: `MetadataTable::get` returns `Result<Option<T>>` and the table
  iterators yield `Result<T>`.
- **BREAKING**: `CilType::fullname()` returns `Arc<str>`; `UserStrings::get`
  returns an owned `U16String`; `derive_pbkdf2_key` returns `Result` and errors
  on an unavailable algorithm instead of silently substituting SHA-256 for SHA-1.
- `CaptureConfig` gains `max_items` and `max_total_bytes` ceilings (10 000 and
  256 MB), and buffer capture is off under a default config, honouring the
  documented "no capture by default" contract. `CaptureContext::new()` sets it
  explicitly, so the "capture what is useful" constructor is unchanged.
- Stale rustdoc `# Errors` contracts across the crate referenced `Error` variants
  that had been deleted. They are rewritten to what the code returns, and
  `deny(rustdoc::broken_intra_doc_links)` plus `RUSTDOCFLAGS: -Dwarnings` in CI
  keeps them accurate — `RUSTFLAGS` does not reach rustdoc, which is why the
  existing `-Dwarnings` never caught them.
- Doc tests run under a concurrency cap: each fenced example is a whole-crate
  fat-LTO link, and one per core exhausts memory on a many-core machine.
- Five new fuzz targets beside `cilobject`, covering the assembly view, the
  signature and custom-attribute blob parsers, method-body decode and bounded
  emulation.

## [0.8.5] - 2026-08-09

### Fixed

- **No licence text was shipped with the crate.** `LICENSE` and `NOTICE` live at the
  workspace root, but the package root is `dotscope/`, and cargo only packages files
  under the package directory — so every published version declared
  `license = "Apache-2.0"` while shipping neither the licence nor the NOTICE.
  Both files now exist inside the package and are included in the published crate.
- `LICENSE` was a symlink to `LICENSE-APACHE`. Symlinks do not survive packaging
  cleanly; `LICENSE` is now a regular file and the duplicate `LICENSE-APACHE` is gone,
  with the README badge and the crate-level doc badge repointed at it.

### Dependencies

- Upgraded `analyssa` 0.4.1 → 0.5.0, which fixes SSA rebuild and phi-transform
  correctness: on a 125 MB reference binary the upstream pass rollbacks went from
  6,094 to 0 and verifier-reported undefined uses from ~28,960 to 0. No API changes
  were needed here.
- Upgraded `comfy-table` 7.2.2 → 8.0.0. The preset-string API was removed in v8;
  `Table::load_preset(presets::NOTHING)` becomes `Table::load_style(presets::NOTHING)`,
  where presets are now `TableStyle` constants. Rendering is unchanged.
- Refreshed all remaining dependencies (`cargo update`), including `aes`, `clap`,
  `thiserror`, and `smallvec`.

### Changed

- Recorded ATRAPS LLC as copyright holder in `LICENSE` and `NOTICE`.
- Dropped the deprecated `authors` field from both workspace members and repointed
  `repository` / `homepage` at the organisation.
- Default branch renamed from `master` to `main`; CI triggers and the fuzzing and
  security-audit job conditions were updated to match.
- Publishing now uses crates.io trusted publishing instead of a stored registry token,
  and refuses to publish a release whose commit is not contained in `main`.

## [0.8.4] - 2026-07-26

### Added

- **Memory optimization pass** (`compiler::MemoryOptimizationPass`): store-to-load forwarding, redundant load elimination, and block-local dead store elimination, every rewrite gated on a Memory SSA alias proof. Registered in the deobfuscation pipeline's normalize phase and enabled by default; disable with `PassConfig::memory_optimization = false`. This reaches the field and array traffic obfuscators use to keep values out of SSA registers, which the register-level passes cannot see through
- **Field-sensitive points-to for CIL** (`CilTarget::field_member_index`): the field's metadata token supplies the stable per-field cell identity Andersen's analysis keys on, so `&o.a` and `&o.b` no longer alias. An unresolved (null) field token falls back to the sound whole-object approximation
- **x86 segment overrides reach the IR**: `X86Memory` gained a `segment` field, decoded from the instruction's explicit prefix, and `fs:`/`gs:`-qualified accesses now lower to `LoadIndirect`/`StoreIndirect` with a distinct `address_space` (257/256, following LLVM's numbering). Alias analysis treats the spaces as disjoint, so TEB/PEB and stack-cookie accesses stop colliding with flat memory at the same displacement. `cs:`/`ds:`/`es:`/`ss:` deliberately stay in the flat default — in flat user mode they share a base, and marking them would let alias analysis prove two names for one cell disjoint
- **Re-exports for analyssa's new alias machinery**: `analysis::{pointsto, address}` modules plus `MemorySsa`, `IndirectLocation`, `ArrayIndex`, `AliasResult`, `MemoryDefSite`, `MemoryPhiOperand`, and `MemorySsaStats`
- **Cross-block value promotion before CFF restructuring** (`deobfuscation::passes::unflattening::spill`): unflattening rewires the CFG, so the SSA has to be reconstructed afterwards — and reconstruction is a reaching-definition problem that can only be solved for values with a storage location. Arguments and locals have one; a stack temporary produced in one block and consumed in another exists only as an SSA name, and the sole record that two names denote the same value is the phi that merges them. Rewiring discards exactly that record, and for an edge the patch *creates* no phi ever described it. Every value crossing a block boundary is now promoted to a local slot before any terminator is touched — the classical "spill temporaries before restructuring" step — so rebuild can recover versions and phi placement for all of them by the ordinary algorithm. This is what makes .NET Reactor NecroBit samples reconstruct at all, and it is correct for any rewiring rather than only the shapes whose phis happen to survive
- **Zero-initialization for undefined SSA definitions** (`SsaConverter`): a new construction phase materializes definitions for variables that had none, following ECMA-335 §I.12.3.2.2 — a typed zero `Const` for primitives and references, and `LoadLocalAddr; InitObj; LoadLocal` for value types. Previously such variables were registered with no defining instruction, so they survived initial construction but vanished the moment the variable table was rebuilt from real definitions
- **Emulation and CFF smoke tests** (`tests/emulation_smoke.rs`): five samples whose deobfuscation depends on emulation or the unflattening tracer producing byte-identical results, each checked for semantic preservation against `original.exe`. The full packer suites take hours; this runs in seconds, so a change to the emulation layer or the tracer is validated against real output rather than only wall-clock time
- **Deobfuscation benchmark** (`benches/deobfuscation.rs`): ConfuserEx and .NET Reactor groups plus a detection-only control, behind `--features deobfuscation`

### Fixed

- **Taint-driven neutralization could produce IR with dangling reads**: `SentinelTaintRemovalPass` and `NeutralizationPass` rewrote every tainted instruction to `Nop` and dropped every tainted phi, destroying definitions that surviving code still read. `PhiTaintMode::NoPropagation` makes phis taint barriers by design, so a phi routinely merges a tainted definition into code the analysis never marks. Both passes now shrink the removal set to a fixpoint (`utils::retain_removable`) — a candidate whose result still has a reader is kept rather than the removal widening into legitimate code. `NeutralizationPass` also excludes its protected `DecryptedString` constants from the candidate set rather than at rewrite time, so branch-target selection sees what is actually removed
- **`AssemblyDependencyGraph::find_cycles` reports participants, not a closed walk**: following analyssa's switch to a single deterministic Tarjan pass, a self-dependency now names the assembly once rather than twice. The stale "modified DFS with three-color marking" documentation was corrected to match
- **CIL emulation fetched instructions in O(n)** (`emulation::engine::context::MethodCode`): every executed instruction cloned the method's entire instruction vector and scanned it linearly for the current offset. A 3-million-instruction run performed 3.2 billion `Instruction` clones — about 1052 per step. Method bodies are now cached per token with an offset-to-index map, and the execution loop borrows the instruction instead of cloning it. Synthetic bodies bypass the cache, since `ILGenerator` can mutate them
- **Emulation rebuilt the assembly context on every instruction**: `loaded_assembly_context` constructed a fresh `EmulationContext` and took an `RwLock` per executed instruction; contexts are now memoized per assembly index
- **`optimize_locals` split values it renumbered** (`SsaFunctionCilExt`): renumbering a local moved its origin but left its rename group pointing at the old slot. `rebuild_ssa` groups variables by rename group while resolving argument/local representatives by origin, so the two views disagreed about which names denote the same local and the value ended up with no reaching definition. Both now move together
- **CFF tracer could escape its visit budget**: entering an expression-switch false arm deliberately resets `total_visits` so each arm gets its own budget. On heavily nested methods that reset fired often enough to make the budget unbounded — a 348-block ConfuserEx method reached 3.3 million block visits against a 50,000 cap. A monotonic counter now bounds total work per trace without changing the per-arm semantics
- **CFF reconstruction produced invalid SSA after block cloning**: cloned blocks duplicated every definition they contained, phi operands survived pointing at predecessors the patched CFG no longer has, and operands were left naming redirected blocks. Clones now allocate fresh variable ids (after state-tainted filtering, which keys on the original ids), phi operands are pruned against the patched predecessor sets and definedness, and redirected operands are resolved through a bounded hop limit
- **Cleanup deleted live types reachable only through another deletion candidate** (#249, fix contributed in #248 by [@agski331](https://github.com/agski331)): `find_unreferenced_types` computed a single step of what is a transitive reachability problem. A candidate rescued partway through a pass never propagated that liveness onwards, so any cluster reachable solely through it was still read as isolated infrastructure — on `reactor_virtualization` that cut the assembly from 854 methods to 45, deleting a VM interpreter whose stubs remain live because nothing devirtualizes it. Reachability is now a worklist drain over a type-level call graph, in `O(V+E)` rather than `O(depth × edges)`. CustomAttribute constructor types are seeded as roots before propagation rather than filtered afterwards, so the types those constructors call survive too, and liveness propagates from a nested type to its enclosing type — deleting an enclosing type cascades to its children through `expand_type_tokens`, which was dropping nested types that live code still called. The deletion set is sorted for a reproducible order
- **Technique cleanup ran whether or not the transformation it implies succeeded**: a technique builds its cleanup request from detection findings alone, so it scheduled the decryptor, its infrastructure type, the initializer and the encrypted data for deletion even when no call site was reversed, leaving those call sites pointing at metadata that no longer exists and emptying the methods holding them. Removal now requires that nothing still calls the decryptor — a successful decryption rewrites its call site to the constant, so the absence of remaining callers is the evidence of reversal. Absence of recorded failures is not, since a decryptor that was never exercised has none either. Note that the caller check reads the SSA call graph, which covers only methods that converted successfully
- **ConfuserEx constant decryption missed builds that differ from stock 1.6.0** (#249): four defects, each masking the next. The blob index was matched against `int32` alone, so builds emitting `T Get<T>(uint32)` yielded no decryptor at all — any integer width is now accepted, the surrounding constraints carrying the selectivity. `stobj` rejected reference types, though ECMA-335 §III.4.29 defines it over any `typeTok` and makes it equivalent to `stind.ref` for reference types, which is what `stobj !!T` becomes at `T = string`. `ldelema` hand-rolled its index match to `I32`/`NativeInt` while `ldelem`/`stelem` share a helper accepting every width, so a `native uint` index aborted emulation. And `stfld` through a pointer to a value-type array element replaced the whole element with the field's value instead of updating the field inside it, which is the path LZMA's bit-decoder struct arrays take
- **ConfuserEx LZMA blobs were rejected or misparsed** (#249): the sniffer required the compressed payload to be smaller than its declared output, but LZMA expands small high-entropy input and the constants blob is XOR-encrypted before compression — a 44-byte blob compresses to 51 and was refused. The header was also modelled as 5 property bytes plus a 4-byte size, while builds calling the LZMA SDK's stream API write the standard 13-byte header with an 8-byte size; reading that as 9 bytes shifts the payload and corrupts the range coder. Both layouts are now attempted and held to the size each declares, and the size ceiling is documented as an allocation guard rather than a property of the format

### Changed

- **Deobfuscating heavily flattened methods is roughly 25× faster**, through changes that leave what the tracer computes unchanged:
  - Forks mark the evaluator instead of copying it, using analyssa 0.4.1's new `checkpoint`/`rollback`. A flattened method forks millions of times and the evaluator's state grows with everything the trace has learned, so copying it per fork was measured at 99% of tracer time. The same journal treatment is applied to the tracer's own visited-state set, whose sole writer only ever inserts
  - Per-block structural facts — dispatcher-target and foreign-dispatcher membership, constant-producer targets, and the overflow-dispatch-site predecessor walk — are computed once per trace rather than per block visit
  - The cross-scope local bridge indexes variables by local slot instead of scanning the whole variable table inside the per-instruction loop
  - `PatchPlan` keeps membership and redirect-target indexes beside its ordered vectors, replacing linear scans that ran once per block of every node in the trace tree
  - Trace nodes store their visited blocks inline (`SmallVec`); a 1200-block method produced 92 million nodes averaging about one block each, so the per-node heap allocation dominated the allocator
  - The per-node instruction log was removed: it recorded operand values nothing read, and its only consumer needed opcodes that are available from the SSA
- **Dependencies**: bumped `analyssa` (0.3.0 → 0.4.1) and added `smallvec` (1.15)

Measured end-to-end on the packer samples, deobfuscating the whole assembly: ConfuserEx `maximum` 63.6 s → 2.0 s, and .NET Reactor `necrobit` — which previously failed to reconstruct at all — 385 s → 15.1 s. Part of that comes from analyssa 0.4.1 rather than from dotscope: alongside the evaluator's `checkpoint`/`rollback`, it batches the rebuild-mode substitution in `eliminate_trivial_phis`, which had been applying one whole-function scan per trivial phi. A rebuild produces trivial phis in proportion to the function, so the round was quadratic — on a 1200-block method it was the single largest cost in the pipeline.

## [0.8.3] - 2026-07-16

### Changed

- **Dependencies**: bumped `analyssa` (0.2.0 → 0.3.0), `num-bigint` (0.5.0 → 0.5.1), `tokio` (1.52.3 → 1.52.4), `clap` (4.6.1 → 4.6.2), `anyhow` (1.0.102 → 1.0.103), and `env_logger` in `dotscope-cli` (0.11.10 → 0.11.11, aligning it with the version `dotscope` already used)

This is a patch release: dotscope's own public API is unchanged. `SsaOp` is not re-exported, `conv_op_for_target` is crate-internal, and the analyssa types dotscope *does* re-export (`BinaryOpKind`, `CmpKind`, `UnaryOpKind`, `PhiNode`, `PhiOperand`, `Target`, `PointerSize`, and the loop/symbolic/dataflow types) are all unchanged in analyssa 0.3.0.

Most of analyssa 0.3.0's correctness fixes target native lifters and do not apply to the CIL frontend: the `ld2r`/`setffr`/`dmb` effect corrections concern AArch64/x86 ops dotscope never emits, and the GVN `ComputeFlags`/`CallClobber` fixes concern native flag and call-clobber markers with no CIL equivalent. Likewise the pointer-conversion signedness fix has no observable effect here — dotscope never emits `PtrToInt`, and `CilTarget::convert_const` declines pointer targets, so `IntToPtr` does not constant-fold. What dotscope does inherit is analyssa's structural GVN value key (replacing a per-candidate `Debug`-string key) and the `SsaEditor::nop_instruction` fix that no longer leaves a dead `result_type` on a removed instruction.

## [0.8.2] - 2026-07-02

### Fixed

- **Fat exception-section header size** (#218): `encode_exception_handlers` emitted the fat exception-handling section header as 6 bytes (`Kind` + 2 reserved bytes + `DataSize`) instead of the 4 bytes mandated by ECMA-335 §II.25.4.5 (`Kind` (1 byte) + `DataSize` (3 bytes)). The two extra bytes shifted the `DataSize` field, so a method written back to disk reported a garbage handler count (e.g. `0x1C0000 / 24 = 76458`) and downstream runtimes (Mono/IKVM) crashed resolving a bogus catch-type token. The header is now exactly 4 bytes and survives a write/parse round-trip

### Changed

- **Dependencies**: bumped `num-bigint` (0.4.6 → 0.5.0), `z3` (0.20.1 → 0.20.2), `quick-xml` (0.40.1 → 0.41.0), `memmap2` (0.9.10 → 0.9.11), `rustc-hash` (2.1.2 → 2.1.3), and `env_logger` (0.11.10 → 0.11.11)
- **CI/CD**: fixed z3 link errors in the CI workflow and corrected the docs.rs / release workflow configuration

## [0.8.1] - 2026-06-24

### Fixed

- **Exception handler encoding — fat-format promotion for many clauses**: `encode_exception_handlers` only switched to the fat exception-handling section format based on per-clause offset/length sizes, ignoring the 1-byte `DataSize` field. With more than 20 clauses (4-byte header + 12 bytes/clause > 255) the small-format `DataSize` byte overflowed, producing a corrupt section. The encoder now also forces fat format when `handlers.len()` exceeds the small-format clause limit (ECMA-335 §II.25.4.5/.6)

### Changed

- **Dependencies**: bumped `log` (0.4.31 → 0.4.33) and `z3` (0.20.0 → 0.20.1)

## [0.8.0] - 2026-06-03

### Changed

- **SSA functionality extracted into the standalone [`analyssa`](https://crates.io/crates/analyssa) crate**: the target-agnostic SSA IR, analyses, and optimization/deobfuscation pass framework now live in `analyssa`, with dotscope providing the CIL-specific host (lifting, type system, codegen). dotscope builds on `analyssa` 0.2.0, which adds the native SSA substrate (SIMD/vector ops, native atomics, wide arithmetic, boolean ops), a fluent SSA builder and verifier-checked editor, and ~3–4× smaller core IR types. The CIL pass scheduler is built on `analyssa`'s `PassScheduler::empty` so the deobfuscation pipeline keeps full control over which passes run
- **Structured parse errors** (**breaking**): parse failures are now reported through `Error::Parse(ParseFailure)` with a `ParseStage`, replacing the stringly-typed `Error::Malformed` / `Error::OutOfBounds` / `Error::HeapBoundsError` variants at parse sites. The `malformed_error!` / out-of-bounds helper macros and `#[non_exhaustive] ParseFailure` give callers categorizable, source-located errors. Code that matched the removed variants must migrate to `Error::Parse(..)`
- **Fallible metadata lookups** (**breaking**): metadata lookup APIs such as `CilObject::method()` now return `Result<_, Error>` instead of `Option<_>`, so a missing or unresolvable token reports a typed error rather than a bare `None`. Callers using `if let Some(..)` / `?`-on-`Option` must switch to the `Result` forms
- **Hardening against malformed/adversarial input**: enabled strict crate lints (`unwrap_used`, `expect_used`, `panic`, `arithmetic_side_effects`, `indexing_slicing` set to `deny`) and reworked the metadata parsers (custom attributes, marshalling, resources, signatures), the validation layer (scanner, schema, raw/owned constraints), and the deobfuscation passes to use fallible, bounds-checked, overflow-safe access. The parser no longer panics on crafted inputs

### Fixed

- **SSA construction — operand corruption**: the placeholder→final variable rename in `SsaConverter` applied cascading by-value replacements, which under `analyssa` 0.2.0's variable-id encoding could collapse a binary operation's operands (e.g. `a - b` becoming `b - b`). The rename is now applied atomically/position-wise, so it is correct regardless of id numbering (handles operand aliasing, swaps, repeated operands, and the reserved placeholder id). This only affected method bodies regenerated from SSA (deobfuscation output)
- **CFF unflattening — expression-obfuscated dispatchers**: state-variable backward tracing (`trace_to_phi`) now follows `neg`/`not`/`conv` wrappers, so ConfuserEx "expression" control-flow flattening (`-(!!state)`-style transforms) no longer hides the dispatcher state phi. `Dispatcher::refresh` reuses the same tracer instead of a shallow, fixed-depth walk
- **CFF unflattening — nested/exception-handler dispatchers**: when a dispatcher's state-setup block is also one of its own switch case targets (common for handler-region CFF), the initial state was not recovered, so the tracer could not seed the state machine and explored every path until hitting its limits — leaving a residual switch and dropping code. The initial state is now recovered from the state phi's constant operand; ConfuserEx control-flow + expression samples fully unflatten again

## [0.7.0] - 2026-05-03

### Added

- **JIEJIE.NET Support**: Full deobfuscation pipeline — control flow flattening, string encryption, constant encoding, resource encryption, typeof obfuscation, array initialization, and infrastructure cleanup. 10/10 test samples pass
- **BitMono Support**: 16 protections covered with PE repair; 18/18 test samples pass. String decryption gated behind the `legacy-crypto` feature (PBKDF2-HMAC-SHA1)
- **.NET Reactor 7.5.0 Support** (partial): basic protections supported; full feature set and virtualization remain in progress
- **Deobfuscation Architecture Overhaul**: moved from obfuscator-focused to technique-based design; added `DelegateProxyResolutionPass`, `OpaqueFieldPredicatePass`, `StaticFieldResolutionPass`, and `SentinelTaintRemovalPass`
- **Emulation Engine Decomposition**: split into `callresolver`, `exhandler`, `typeops`, `dispatch`, `generics`, and `tracefilter` modules; extended BCL runtime with 600+ stubs
- **ILDasm Formatter Library**: full ILAsm-compatible text output in `dotscope::formatting` (~16 submodules) covering structural directives, type system, members, exception handlers, custom attributes, security, generics, resources, COM interop (`.vtfixup`/`.vtentry`/`.export`), and section-aware `.data` directives
- **VtFixup Parsing**: support for mixed-mode assemblies via vtable fixup table parsing
- **AssemblyRef and MemberRef Cleanup**: cleanup pipeline now removes unused `AssemblyRef` and `MemberRef` entries
- **Cascading Output Cleanup**: improved cleanup system for better cascading removal of dead metadata in output binaries
- **Metadata and Type System API Extensions**: `CilFlavor::byte_size`, `FieldQuery`, and the `wellknown` module

### Changed

- **File Backend Migration**: `File` now uses [`cowfile`](https://crates.io/crates/cowfile) (0.2.1) for OS-level copy-on-write memory maps (`MAP_PRIVATE` / `PAGE_WRITECOPY`); PE repairs are applied in place to the mmap with only touched pages copied by the OS
- **Metadata Flags Refactor**: migrated metadata flag types to a type-safe `metadata_flags!` macro
- **SSA Rebuild Refactor**: reworked `SsaRebuild`-related logic to improve SSA construction reliability and stability
- **CI/CD**: removed macOS Intel from the CI/CD pipeline
- **Dependencies**: replaced the `rsa` crate temporarily due to a published CVE; bumped other dependencies

### Fixed

- **Codegen — Address-Taken Locals**: codegen no longer erases required address-taken locals
- **CFF Unflattening**: missing `BranchCmp` cases caused traces to abort early; now handled
- **CFF Unflattening**: regressions from earlier refactoring resolved
- **Inlining Race**: parallel pass execution could miss inlining candidates due to a race; fixed
- **CALLI in SSA Construction**: now uses metadata for correct stack handling
- **CALLI in `SsaConverter`**: previously missing handling added
- **Exception Handler Hardening**: improved validation/handling of malformed handlers
- **Exception Handler Encoding**: corrected size encoding for exception handlers
- **Exception Handler Codegen**: fixed handler generation in codegen
- **String Heap Compaction**: substrings within removed strings no longer cause incorrect compaction
- **DeobfuscationConfig**: `detection_threshold` was not being applied properly
- **Lenient Mode**: lenient flag is now properly propagated for force analysis
- **x86 Decoder**: added support for `call $+5` trampolines
- **PureLogs Reliability**: multiple analysis fixes
- **.NET 10 Compatibility**: improvements for .NET 10 assemblies
- **Feature Gating**: resolved unused warnings for feature-gated APIs

## [0.6.0] - 2026-02-12

### Added

- **Analysis Module**: Control flow graph (CFG), SSA form, dataflow analysis (SCCP, liveness, reaching definitions), callgraph construction, def-use chains, range analysis, taint analysis, algebraic simplification, x86 native analysis, and symbolic execution
- **Emulation Engine**: Full CIL interpreter supporting 200+ opcodes, copy-on-write memory model with fork support, 200+ BCL method stubs, exception handling, thread model, and process builder
- **Deobfuscation Pipeline**: 20 optimization passes, SSA-to-CIL code generation, detection framework, state machine analysis, and ConfuserEx obfuscator support
- **ConfuserEx Support**: Anti-tamper, anti-debug, anti-dump, constants (normal, dynamic, CFG, x86 cipher modes), control flow (normal, expression, x86 predicates), reference proxy (mild + strong), marker cleanup, invalid metadata repair, resource decryption — covers all standard preset protections (Minimum through Maximum)
- **Obfuscar Support**: Detection (scoring-based identification via helper type structure, XOR decryption loop, null parameter names), string decryption (emulation-based via `DecryptionPass` pipeline), SuppressIldasmAttribute removal, infrastructure cleanup (helper types, nested types, fields, accessor methods) — 6/6 test samples pass covering default, strings-only, rename-only, unicode, and maximum configurations
- **Writing Pipeline**: Streaming PE generation, heap compaction, token remapping, IL patching, resource section generation, import/export tables
- **Codegen Pipeline**: Complete SSA destruction, register allocation, phi elimination, instruction selection, exception handler remapping, local variable signature generation
- **TypeQuery and MethodQuery System**: Structured query system for type and method resolution
- **Workspace and CLI Tool**: Migration to Cargo workspace with first prototype of the `dotscope-cli`

## [0.5.1] - 2025-11-28

### Fixed

- **Package Size**: Excluded legacy Mono test directories (mono_2.0, mono_3.5, mono_4.0, mono_4.5) from crate package to reduce size from ~160MB to ~6MB compressed, staying within crates.io limits
- **Documentation Examples**: Updated all doc examples to use mono_4.8 test samples for consistency
- **Blob Heap Modification Remapping**: Fixed table index remapping when modifying existing blobs that grow larger than their original size. Previously, blob modifications that didn't fit in place were appended to the heap but table references weren't updated, causing validation failures

## [0.5.0] - 2025-11-27

### Added

- **Multi-Assembly Project System**: New `ProjectLoader` for loading and analyzing multiple assemblies with automatic dependency resolution
- **Assembly Dependency Analysis**: Comprehensive dependency graph analysis with cycle detection and topological sorting
- **Assembly Identity System**: Cryptographic identity tracking with strong name and public key support
- **Zero-Copy Resource Parsing**: New `ResourceTypeRef<'a>` and `ResourceEntryRef<'a>` types for memory-efficient resource access
- **Additional Resource Types**: Support for `Stream`, `Decimal`, `DateTime`, and `TimeSpan` resource types
- **Nested Class Cycle Detection**: Validation system now detects circular nesting relationships in metadata
- **Parser Enhancements**: Transactional parsing with `transactional()` and non-advancing `peek_*` methods
- **Performance Benchmarks**: Extended benchmark suite covering COR20 header, method bodies, signatures, streams, and security parsing

### Changed

- **Error System Redesign**: Comprehensive refactoring of error types for clarity and consistency
  - `Error::Error` → `Error::Other`
  - `FileError` → `Io`
  - `GoblinErr` → `Goblin`
  - `BranchTarget*` errors consolidated into `BranchTargetOutOfRange`
  - Validation errors renamed for consistency (e.g., `InvalidFieldType` → `FieldTypeInvalid`)
  - Unused error variants removed
- **MethodAccessFlags**: Changed from bitflags to a pseudo-enum to correctly represent mutually exclusive access modifiers per ECMA-335
- **Inheritance Validator**: Optimized algorithm for significantly faster validation on large assemblies

### Fixed

- **Resource Encoder Bug**: Fixed string length encoding using incorrect format (ECMA-335 compressed uint instead of .NET BinaryWriter 7-bit encoded int)
- **ECMA-335 Compliance**: Added handling for I.8.5.3.2 narrowing accessibility restriction exception
- **OOM Prevention**: Added checks to prevent out-of-memory crashes from corrupted or invalid counts in malformed assemblies
- **CI/CD Improvements**: Fixed cross-platform test compilation for Windows, macOS, and Linux with proper architecture detection

### Improved

- **Documentation**: Extensive documentation improvements across all modules with better examples and ECMA-335 references
- **ECMA-335 Correctness**: Multiple fixes to improve spec compliance throughout the codebase
- **Test Infrastructure**: Enhanced test support for different runtimes (CoreCLR, Mono) and platforms
- **Performance**: Various optimizations for parsing and validation operations

## [0.4.0] - 2025-08-19

### Added

- **Assembly Encoder and Builder System**: Complete CIL assembly encoder and builder implementation with high-performance benchmarks
- **High-Level Builders**: Added builders for classes, enums, events, interfaces, properties, and methods with full CIL method body support
- **Binary Modification Capabilities**: Full binary modification support with method injection and exception handler support using label-based targeting
- **PortablePDB Support**: Complete PortablePDB parsing implementation for enhanced debugging information
- **EnC (Edit and Continue) Tables**: Support for Edit and Continue metadata tables
- **Validation System**: Comprehensive validation framework to ensure modified binaries remain valid and loadable
- **Binary Serialization**: Capability to write modified assemblies back to disk

### Changed

- **Module Organization**: Renamed `disassembler` module to `assembly` in preparation for encoder implementation
- **File Structure**: Removed `self_reflecting` from File structure, storing PE information locally for improved performance

### Fixed

- Fixed regression in size field length calculation
- Fixed multiple issues causing modified binaries to be invalid
- Fixed clippy warnings for latest Rust versions
- Various binary modification stability improvements

### Improved

- Enhanced integration testing with Mono runtime verification
- Improved PE file handling and structure
- Better separation between parsing and encoding functionality
- Updated examples and documentation

## [0.3.2] - 2025-06-17

### Fixed

- Wrong release sequence for 3.1, this corrects the changes necessary

## [0.3.1] - 2025-06-17

### Improved

- Enhanced overall documentation across the codebase with better examples and clearer explanations

## [0.3.0] - 2025-06-14

### Added

- Implemented missing pointer tables (FieldPtr, MethodPtr, ParamPtr, EventPtr, PropertyPtr)
- New builder system and test scenarios for complex .NET features
- Support for parsing XML-based security permission sets

### Changed

- Reorganized metadata table structure for better maintainability
- Better separation of raw tables, loaders, and owned types

### Improved

- Extended marshaling support for native interop scenarios
- Improved validation of various entries while loading the binary
- Performance optimizations
- Improved type resolution and generic parameter handling
- Expanded test coverage with crafted test cases

## [0.2.1] - 2025-06-11

### Fixed

- **Type System Issues**: Resolved critical issues with type flavor classification and inheritance resolution
- **Method-to-Type Associations**: Fixed method discovery and association with declaring types  
- **Interface Relationships**: Improved interface inheritance chain resolution
- **Type Flavor Determination**: Added proper logic to classify value types, interfaces, and classes correctly
- **Parser Stability**: Enhanced robustness and error handling in metadata parsing

### Added

- **Enhanced Test Coverage**: Expanded test coverage analysis and validation for complex .NET features

### Improved

- **Type System Validation**: More accurate type classification and inheritance analysis
- **Test Infrastructure**: Enhanced validation and coverage analysis

## [0.2.0] - 2025-06-10

### Added

- **Custom Attribute System**: Complete implementation with constructor/property resolution and support for complex parameter types
- **Enhanced Generic Type System**: Improved MethodSpec handling, corrected generic parameter resolution (`T -> System.Int32`), improved type builder and resolver
- **Method Analysis Framework**: Improved IL disassembly + API

### Fixed

- **Type Safety**: Replaced unsafe casting with proper bounds checking and overflow detection
- **Memory Management**: Improved method-to-type associations and type flavor classification
- **Dependencies**: Updated all dependencies to address security advisories #4, #5, #6

### Changed

- **Breaking**: MethodSpec architecture - `CilType.generic_args` now contains MethodSpec instances instead of direct CilTypeRc
- **Performance**: Replaced RwLock with `boxcar::Vec` for better lock-free concurrency
- **Security**: Enhanced input validation and overflow protection for malformed assemblies

## [0.1.0] - 2025-06-08

### Added

#### Initial Release

dotscope is a Rust library for parsing and analyzing .NET assemblies (PE files with CLI metadata).

#### Core Features

- **PE File Parsing**: Read .NET assemblies from files or memory buffers
- **Metadata Analysis**: Parse ECMA-335 metadata tables, strings, and blob heaps
- **CIL Disassembly**: Decode IL bytecode into readable instructions with basic block analysis
- **Type System**: Access type definitions, method signatures, and field information
- **Resource Extraction**: Read embedded resources and manifest data

#### API Highlights

- `CilObject::from_file()` and `CilObject::from_buffer()` for loading assemblies
- Access to metadata tables (TypeDef, MethodDef, Field, etc.)
- CIL instruction decoding with control flow analysis
- Type resolution and signature parsing
- Comprehensive error handling with detailed context

#### Quality & Testing

- 90%+ test coverage with 400+ unit tests
- Fuzzing infrastructure for robustness testing
- Integration tests with real .NET assemblies
- Memory-safe parsing with bounds checking

#### Known Limitations

- Custom attribute parsing is not fully implemented
- Some advanced signature types need refinement
- Resource limits for DoS protection not yet implemented
