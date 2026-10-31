# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Code generation is rebuilt around the order it emits in** (#288). Operations are emitted
  in SSA order, a value read once moves to its use only where analyssa's `FoldForest` proves
  the move unobservable, slots are shared by analyssa's `Gathering` and typed from every value
  they hold, and phi copies are one parallel copy per edge. This closes the class of stale,
  overwritten and never-written slot reads behind #288.
- **Validators enforce only ECMA-335 rules and what the runtime refuses.** Content scanning,
  limits ECMA-335 does not set, "suspicious" values and checks nothing can trigger are gone,
  so validation no longer fails assemblies the runtime loads.
- **The writer never retargets a reference to a row it deletes.** It used to point such a
  reference at the next surviving row; now the write fails with `Error::DanglingReference`,
  or writes a null reference under `GeneratorConfig::with_dangling(DanglingPolicy::Null)`.
- Every documentation example is real code that compiles: examples that were `ignore`d and
  had drifted from the API (nonexistent methods such as `parse_from_pe`, wrong paths and
  arguments) are rewritten, and examples of crate-private items run as unit tests.
- Output is deterministic: methods are emitted in token order and array data fields are named
  by interning order. A load that fails names the first failing row or body in token order,
  not whichever thread failed first.
- Strength reduction is analyssa's `StrengthReductionPass`, and sort order is validated
  (`ValidationConfig::enable_sort_order_validation`).
- **BREAKING**: `SsaCodeGenerator::compile` is all or nothing: a refused method leaves the
  tables, heaps, stored data and interning as they were. `generate_with_assembly` is removed.
- **BREAKING**: A coded index whose tag names no table reads as null, as the CLR reads it,
  keeping the stored value in `CodedIndex::unassigned_tag`. `TableInfo::decode_coded_index`
  returns `Option`, and `CodedIndexType::tables()` lists only the tables a coded index names.
- **BREAKING**: `TablesHeader::from` and `TableInfo::new` take `wide_columns`;
  `CustomAttributeRaw::to_owned` takes `&Arc<TypeRegistry>`;
  `CompilerContext::build_ssa_call_graph` and `build_effective_call_graph` take the assembly;
  `Method::parse` takes `assembly::DecodedBodies`; `Technique::byte_transform` takes
  `&mut Detection`; `Pe::from_goblin_pe` takes the bytes goblin parsed, and
  `NativeExports::from_pe_exports` the export directory's `PeExportHeader`.
  `PeImport::dll`, `ImportDescriptor::dll_name` and `NativeImportRef::dll_name` are
  `Arc<str>`, one string for a descriptor's imports.
- **BREAKING**: `Identity::Token` holds the token's 8 bytes in the order .NET prints them, and
  `Identity::to_token` returns them. `Method::varargs` and `VarArg` are removed: a method
  definition has no vararg types (a call site's are on `SignatureMethod::varargs`).
  `ParamList` and `Method::local_vars` are `LazyList`s, validation contexts and their factory
  functions take no thread pool, and `TypeRegistry::registry_link` takes `&Arc<TypeRegistry>`.
- **BREAKING**: A branch's operand is its target (`Operand::Target(rva)`). Lists that rows
  attach to are `utils::RowList`s in table order. `Resources` is keyed by ManifestResource
  token.
- **BREAKING**: Custom attribute values follow ECMA-335 II.23.3's grammar, so every value
  encodes back to its blob: `String`, `Type` and `Array` hold `Option` for null, `Array`
  names its element type, `Char` is the UTF-16 code unit (`u16`), a new `Boxed` holds an
  `object` argument with its own type, and a named argument's `arg_type` is a
  `FieldOrPropType`. `I`, `U` and `Void`, which no attribute argument can be, are gone, and a
  constructor taking one is refused. The encoder writes array counts as `uint32` (they were
  compressed), null strings and arrays as null, and named enum and array arguments, which it
  refused; `encode_field_or_prop_type` is new.
- **BREAKING**: Marshalling descriptors encode back to their bytes. An optional field is
  present when bytes remain, so a parameter index of 0 is no longer read as an end marker;
  `NativeType::Array` gains `flags` (the field after the element count), `NATIVE_TYPE_MAX` is
  `NativeType::Unspecified` instead of `End`, `SafeArray::variant_type` is an `Option` read as a
  compressed VARTYPE with a length-prefixed type name, and a custom marshaler's four
  length-prefixed strings are read in ECMA-335's order (the marshaler's type was read as the
  cookie, with its length byte in it). `MarshallingInfo::additional_types` is gone: a
  descriptor is one native type, and the extra types were written where the first type's
  optional fields are read, so LPSTR plus a `Boolean` encoded LPSTR with SizeParamIndex 2.
  An array's element type and a pointer's target are a `NATIVE_TYPE` byte
  (`NativeType::from_tag` reads one), as the format holds them: they were decoded as whole
  native types, so `LPArray` of `LPStr` with `SizeParamIndex = 5` read the index as the
  strings'. The encoder refuses optional fields out of order (`flags` without `num_element`,
  a SafeArray type name without its VARTYPE), and `FieldMarshalBuilder::fixed_array` writes a
  ByValArray, where it wrote an ARRAY with a raw 4-byte size.
- **BREAKING**: Declarative security follows the runtime. `SecurityAction` has
  `CorDeclSecurity`'s values (they were off by one: an assembly's `RequestMinimum` read as
  `RequestOptional`), gains `Request`, loses the `*Choice` variants and displays an
  undefined value as its number; `SecurityPermissionFlags` has `SecurityPermissionFlag`'s
  values and names (`SECURITY_FLAG_UNMANAGED_CODE` is 2) and `parse`. A permission's
  properties are custom attribute named arguments (`NamedArgument`, `ArgumentType` and
  `ArgumentValue` are gone), so a binary set encodes back to its bytes and an enum property
  stays an enum; `Permission` keeps the class name as the set writes it, with `type_name`,
  `assembly_name` and `is_class`, so its predicates match the assembly-qualified attribute
  classes real sets name. XML sets are read as UTF-16 (they were refused) with entities
  unescaped and the root's `Unrestricted`; the encoder writes XML as UTF-16, keeps a value's
  tabs and newlines (attribute normalization turned them into spaces), and refuses characters
  XML cannot hold. The invented
  `BinaryCompressed` format, `PermissionSetEncoder` and `IDENTITY_PERMISSION` are removed
  (`BinaryLegacy` is `Binary`). The builders write the attribute classes with a typed `Flags`
  enum and `encode` takes no format, and `DeclSecurityBuilder::unrestricted_permission_set`
  writes a real unrestricted set. The security validator accepts every defined action
  (it refused `NonCasInheritance`) and no longer scans XML sets' text. A type's, method's or
  assembly's `security` is a `RowList` of every `DeclSecurity` row it has, in table order: one
  slot kept a single declaration, whichever loader thread set it first, so a type's
  inheritance demand or link demand was dropped at random.
- **BREAKING**: Method bodies encode back to their bytes. `MethodBody` gains
  `exception_format`, the exception section's format and `DataSize` as read, which
  `encode_exception_handlers` now takes (a fat section for clauses the small format holds,
  and a `DataSize` without the header as AsmResolver writes it, were rewritten), and a finally
  or fault clause keeps its token field. Data sections are walked as CoreCLR walks them: one
  of another kind no longer ends the walk, only the first EH table is read (later ones were
  merged in), and a truncated one is an error in strict decoding, where its clauses were
  dropped. The cap of 1024 handlers is gone. `Method::encode_body` and `encoded_size` encode
  as `MethodBody::write_to` does, keeping the header format. No body with `InitLocals` is
  written with a tiny header, which cannot state it (it also zeroes `localloc` memory);
  `MethodBodyBuilder` sets it only for a body with locals or a `localloc`.
  `exception_structure_defects` reports every way a body's clauses break ECMA-335's structure
  rules (nesting, `endfinally`/`endfilter` placement, `leave` out of a finally, boundaries
  inside instructions), where `validate_protected_region_flow` stopped at the first flow defect.
  `InstructionEncoder::encode_decoded` encodes decoded instructions over their code, each at
  its place with its branch form, the bytes no path reaches kept: decoded code encodes back to
  itself, which `Method::encode_body` failed to (a decoded branch names its target, which
  `emit_instruction_decoded` now refuses) while computing a stack depth that ignored calls.
- **BREAKING**: `EmValue` converts from a `ConstValue` with `TryFrom`, refusing what only a
  process can allocate (user strings, decrypted strings and arrays) and vector constants,
  which `From` turned into null or a heap offset; a runtime handle is its token as a native
  int, as `ldtoken` pushes it.
- **BREAKING**: `Property::fn_other` and `Event::fn_on_other` are `RowList`s: ECMA-335 allows any
  number of other methods, and a second one failed the load. The IL listing prints every
  `.other`.
- **BREAKING**: A float constant is `ConstValue::Float(FloatBits)`, exact for every format
  (analyssa); `ConstValue::F32` and `F64` are gone. `analysis::FloatBits` and `FloatFormat`
  are re-exported, and `ConstValue::from(f32 | f64)` and `as_f32`/`as_f64` build and read
  CIL's two formats.
- **BREAKING**: `ConstantRaw` gains `padding`; `CodedIndex::encode` writes a coded index as
  it was read.
- **BREAKING**: `SignatureMethod` gains `unmanaged` and `calling_convention` /
  `set_calling_convention`, and a method signature whose calling convention names no method
  signature kind is refused. `FnPtrSig` carries its return and parameter modifiers.
- **BREAKING**: Signed compressed integers follow ECMA-335 (rotated two's complement):
  `utils::write_compressed_int` returns `Result`, as does `write_compressed_uint`, which
  refuses a value past `0x1FFF_FFFF` it wrote as bytes of another length;
  `ArrayDimensions::lower_bound` is `Option<i32>`, and `InstructionEncoder::emit_call` takes a
  `u16` argument count.
- **BREAKING**: Sequence points follow the Portable PDB format
  (`SequencePoints { local_signature, points }`, `to_bytes` returns `Result`), and the
  re-exported analyssa types take and return `FxHashMap` / `FxHashSet`.
- **BREAKING**: Custom debug information is decoded by kind: `CustomDebugInfo` has a variant
  for each of the 14 kinds the Portable PDB specification and the compilers define (an
  unknown kind keeps its blob), `encode_custom_debug_blob` writes one back, and an embedded
  source keeps its stored bytes until `embedded_source_text` inflates them, bounded by the
  size they state. `CustomDebugKind::from_guid` takes a `uguid::Guid` and `guid` replaces
  `to_guid_bytes`; `CustomDebugParser` and `debug_guids` are gone (`pdb::guids` holds the
  GUIDs) and `data_size` returns `Result`. `CustomDebugInformation` gains `parent_token`,
  `Document::hash_algorithm` is an `Option` (nil for a document without content) and
  `LocalConstant::signature` is a `LocalConstantSig`, holding the value.

### Added

- `Root::stream`, `Root::tables_stream` and `Root::unread_streams`: the stream the runtime
  reads for each name, and the ones it ignores.
- `Param::from_signature`, and `type_tokens` on the signature types (generic method
  instantiations included): every TypeDef, TypeRef and TypeSpec a signature names, custom
  modifiers included. `encode_method_spec_signature` writes a generic method instantiation.
- `TokenResolver::generic_definition`: the type a generic instantiation's TypeSpec
  instantiates.
- `CilAssembly::find_corelib_type`: a core library type as the module names it, its TypeRef
  or, in the core library itself, its own TypeDef.
- `CilObject::fields`: every field definition by token; `CilObject::custom_attributes`:
  every custom attribute by token.
- `metadata::exports::ExportForwarder`, the type `NativeExports::forwarders` returns.
- `dotscope::io`: the binary codecs (compressed integers, endian readers and writers, 7-bit
  lengths, prefixed strings), with the compressed-integer codecs in the prelude.
- Translation validation of every generated body (`compiler::validate_lift`) and ECMA-335
  protected-region checks. A refused body keeps its original IL and is recorded as
  `EventKind::CodegenRefused`.
- SSA forms for `arglist`, `mkrefany`, `refanyval` and `refanytype`; methods decoded from
  their handlers as well as their entry (`decode_blocks_with_handlers`).
- Deobfuscation: `bitmono.tokens`, `bitmono.locals` and `netreactor.emptyresource`, one
  metadata repair registry (`deobfuscation::repairs`), and `INLINED_METHOD_REMOVED`, the event
  message for a program method removed because every call to it was inlined.
- Exports of functionality that was built but unreachable: `repair_pe`, `emulation::tokens`,
  control flow unflattening (`unflatten`, `CffDetector`), the conflict resolution types,
  analyssa's CIL aliases and the x86 condition classifiers.
- Portable PDB: every load reads the PDB the image embeds, or else its own debug tables, and
  `CilObject::pdb()` gives it, every table decoded, with queries by method, document and
  parent; `with_pdb` and `with_pdb_bytes` attach a standalone `.pdb` (in the load's mode; one
  written for another image is refused). `PdbMetadata`, `embedded_portable_pdb`,
  `codeview_pdb_id`, `File::debug_directory`, `LocalConstantSig`, `document_name`,
  `DocumentNameBlob` and `parse_import_records` read the parts, and encode them back. The
  System.Reflection.Metadata oracle checks PDBs too.
- `testkit` feature: the test support dotscope's own tests share. Hidden and unstable,
  outside the semver surface.

### Removed

- `analysis::conv_op_for_target`: analyssa's `SsaOp::conversion_between` builds the same
  conversion.
- The `skip-expensive-tests` feature: the test tiers select tests instead.

### Fixed

#### Loading and metadata

- Portable PDB data reads as the compilers write it: document names are decoded from their
  DocumentNameBlob (they were the blob's bytes), local constants hold their values (they were
  read as field signatures), the custom debug information kinds have their GUIDs (Compilation
  Options' GUID was named compilation metadata, and options had a GUID no compiler writes),
  and `DocumentBuilder` writes the hash algorithm and language GUIDs with their real values
  in heap byte order. A standalone or embedded PDB was never read, and the debug tables in an
  image were loaded and dropped.
- `malformed_error!` with a literal message formats its inline arguments (a dozen messages
  printed `{name}` as it is).
- Stream directories, the `#~` ExtraData word and `#JTD` minimal-delta tables are read as
  the CLR reads them, by rules measured on .NET Framework 4.8 and CoreCLR. ConfuserEx's
  "invalid metadata" images load (#289).
- An image holding a coded index whose tag names no table writes, modified or not (#290).
- Bytes at an RVA are read as the runtimes map them, by one mapping (`SectionMap`, through
  `File::rva_slice` and `File::section_bounded`): a section is its VirtualSize bytes, its raw
  data then zeros, measured on the .NET Framework, CoreCLR and Mono. Method bodies, field
  data, resources, the debug directory, VTable fixups and the CLR header no longer read past
  their section into the next one's bytes, uninitialized field data reads as zeros, and the
  writer keeps a section of VirtualSize 0 or with raw data past the file, and refuses field
  data it cannot read rather than copying other bytes. Where sections overlap, a file offset
  maps to the RVA that maps back to it (`SectionMap::offset_to_rva` returned the shadowed one).
- The metadata root's version string is its UTF-8 text up to the terminator (`Root::version`
  kept the padding NULs and read each byte as a Latin-1 character, so a non-ASCII version
  misplaced the stream directory), any text is accepted (an empty version, or one not
  starting with `v`, was refused, yet the .NET Framework, CoreCLR and Mono run it), and a
  written root always terminates it, with `Root::version_field_size` giving the field's
  padded length.
- Array signatures no longer misparse the types after them (3,392 corpus methods now lift),
  and lower bounds are signed. Signatures parse in one pass in stream order, bounded by the
  tree's height across function pointers and by their bytes: a local signature of 5,000
  generic locals, or an instantiation with 2,000 arguments, is no longer refused (a node
  budget and a nesting count that counted siblings refused them), and the caps of 1,024
  parameters and 256 generic arguments are gone. A vararg call site's varargs are those its
  `ParamCount` states (they were read to the data's end), and an END byte where a type belongs
  is refused rather than read as `void`.
- Custom attribute arguments are read by the constructor's signature, not its Param rows,
  enums by their underlying type, and named arguments in ECMA-335 order. An enum no loaded
  assembly defines takes the size that ends the blob, not `int`'s: mscorlib's byte-sized
  `SecurityRuleSet` kept 72 Mono framework assemblies from loading. The cap of 1024 named
  arguments is gone. An enum is its one instance field, whatever it is named (one named other
  than `value__` was not an enum), and a native-integer enum, which no attribute can hold, is
  no longer given the host's pointer width.
- Imported structs are value types, a type's flavor no longer depends on loader timing, a
  sealed class with sequential or explicit layout is no longer taken for a value type,
  `System.ValueType` and `System.Enum` themselves are classes, and core library types come
  from the scope `System.Object` is imported from. A generic instance of a nested type is
  nested where its definition is however the loaders are scheduled (it lost its enclosing
  type when type specifications loaded first), takes its definition's name rather than one
  with an invented arity suffix, and no longer copies a base its definition may not have had
  yet; `TypeBuilder::generic_instance` refuses a count its arguments do not match. The IL
  listing writes a type specification used as a constraint, interface, event or caught type
  with its arguments.
- In a project, each assembly's registry lists only its own types: sources were keyed by the
  Assembly row token, which is `0x20000001` in every assembly.
- A StateMachineMethod row loads: its loader ran before the methods it names, so every row
  failed, and a strict load refused the image. Loaders declare every table they read.
- Token resolution picks by signature; a body shared by several methods is decoded once;
  sequence points load.

#### Validation

- Validators accept what the runtime loads: Retargetable and WinRT references, SHA384 and
  SHA512, sealed classes with a large explicit layout, static virtual interface members,
  generic parameters that allow ref structs, `UnsafeAccessor` methods, a `newslot` method
  beside a final one of the same signature, arrays of sealed types, static fields in
  interfaces, and public types extending internal types or implementing internal interfaces.
  Every Mono 4.8 and .NET 10 runtime assembly now loads as one project; six were refused
  before. An overload is no longer taken for an override: overrides match by signature, so a
  class that seals one overload of a method (Roslyn's `SemanticModel`) loads.
- Rules that never fired check what they name: ownership and dependency checks that skipped
  every type the assembly defines, unresolved types, inheritance depth, concrete types with
  abstract methods, method signatures past the blob heap, and change sets whose field list
  starts past the Field table. An interface with any base type is refused, as CoreCLR does.

#### Write path and cleanup

- The writer sorts the tables the format requires sorted and writes field data of any size.
- A delete made right after an insert of the same row could lose to it: table operations were
  stamped with wall-clock microseconds, which repeat within a tick. `TableOperation::new` now
  takes a process-wide logical timestamp, unique and increasing in creation order.
- Table builders start a new row's field, method, parameter and scope lists at the next row
  instead of claiming rows of other entries.
- `CilAssembly::add_cleanup` keeps the first request's settings and narrows them with later
  ones: it merged the request into a default one, so `remove_empty_types` and
  `remove_orphans` set to false did nothing.
- Cleanup keeps what surviving metadata still names: types named only through custom
  modifiers, the virtual methods filling vtable slots, and methods and fields named through
  MethodSpec and MemberRef tokens. It removes protection methods with their call sites, and
  `<Module>` members with Assembly access become Public rather than Private.
  `CleanupStats` counts each deleted row once; a row two passes removed was counted twice.
- Every column that can name a TypeRef, TypeSpec, MemberRef, ModuleRef, AssemblyRef or File
  keeps that row through cleanup, as do the signatures of `calli` call sites and generic method
  instantiations and the code of exception filters. MemberRefs a MethodImpl names, event types,
  the ModuleRef of a global function reference, and the AssemblyRefs of type forwarders and
  external resources were removed, failing the write or dropping the forwarders.
- After rows are deleted, only blobs a signature column references are renumbered, each read
  as its column's kind. Every blob was tried as a signature before, so an attribute value or
  constant that happened to parse as one was rewritten and truncated, and generic method
  instantiations were never renumbered. A signature naming a deleted type is now a dangling
  reference like any other.
- Portable PDB data in an image writes back as it reads. Blobs naming rows (sequence points,
  local constants, imports, a type's documents, an async method's awaits) are renumbered with
  the rows, and document names and imports, which name blobs, are written once those blobs
  are placed, so a rebuilt heap no longer leaves them pointing at other blobs. The eight debug
  tables, the pointer tables and AssemblyRefProcessor/OS resolve a builder's placeholders and
  follow deleted rows (they were written as they were), and ManifestResource follows a
  deleted ExportedType. `DocumentBuilder` writes a DocumentNameBlob (it wrote the raw path),
  and `ImportScopeBuilder::declarations` takes typed imports.
- A public key token computed from a key prints in .NET's order (`b77a5c561934e089` for the
  ECMA key): it printed reversed and never equalled the same token read from a reference.
- `.resources` streams are written as `ResourceWriter` writes them and as the runtime reads
  them: no length prefix of their own (an embedded one had two), padding counted from the
  magic, names under the runtime's XOR hash over UTF-16 units in signed order, and 7-bit
  lengths. Mono's `ResourceManager` finds every name written (`tests/oracle/resources`). The
  reader counts the padding from the magic as the runtime does, where it skipped "PAD" bytes
  that could include a hash, and `ResourceType::data_size` counts a string's 7-bit length.
- A load validates its raw stage once, with one reference scan, on the global thread pool: it
  ran the raw stage twice and built a private thread pool per engine, and the token integrity
  check walked every row referencing a popular target once per such row.
- A method allocates no empty parameter or local lists, and linked type registries no longer
  keep one another alive: every project leaked all its registries.
- A replacement heap (`string_add_heap` and its siblings) that does not parse is written as
  it is, but changes to it are refused with `Error::LayoutFailed`: the writer dropped it and
  kept only the additions, leaving every reference into it dangling.
- The native import and export tables are read entry by entry, as the Windows loader walks
  them, instead of from goblin's lists, which left out what they could not read and listed
  only named exports, without ordinals. An image whose export table holds an RVA past file
  offset 0xFFFF loads (that offset was taken for an ordinal), a written export table keeps its
  ordinals, ordinal base, DLL name, forwarders, unnamed and aliased exports, and an import
  reads with its hint (`PeExport` gains `ordinal` and `forwarder`, `PeExportHeader` is new,
  and `Pe` records `import_error` and `export_error`). The writer keeps an import or export
  directory that lists nothing or whose size reads 0 (BitMono's), and refuses a table it
  could not read in full rather than writing it without what it could not read.
  `NativeExportsBuilder` sets the DLL name it is given
  (`CilAssembly::set_native_export_dll_name`), and `UnifiedExportContainer::total_count`
  counts a forwarder once. Tables that share lookup tables or names read as the loader reads
  them, but only as far as their entries and names, counted as if unshared, fit in the file:
  a 64 KB file expanded to 13 million imports (1.7 GB). Duplicate imports are found without
  a scan, the unified import views are built once by the first reader, and forwarder
  strings are written in ordinal order.
- `repair_pe` repairs any `NumberOfRvaAndSizes` past 16, as the loader reads only 16, not only
  BitMono's 0x13, and repairs a CLR directory entry only where the image declares one inside
  its optional header (it wrote into what follows fewer directories). Relocating a resource directory walks each directory and data entry once:
  entries sharing a subdirectory or data entry moved it by a multiple of the delta, a tree
  that fans out took exponential time, and directories that overlap are read up to the
  section's size.
- The emulator charges a hook's native work, PBKDF2 rounds and RSA exponentiation, to the
  run's instruction budget (`EmulationThread::charge_work`): a costly call ends the run with
  `LimitReached` as a long loop would, where `Rfc2898DeriveBytes` threw past 100,000
  iterations, a count .NET accepts. A count that is not positive throws as in .NET, and
  `GetBytes` on null throws rather than returning zeros. BitMono's static string decryption
  is held to the emulation budget and no longer swaps in default parameters for a large
  iteration count.
- The emulator's `ldlen`, `ldelem`, `stelem` and `ldfld` read the heap object in place: each
  copied the whole object, so a loop over an array allocated in proportion to its square
  (228 MB to XOR a 1,472-character string). `ManagedHeap::with_object` is new.
- The writer's output grows when a write runs past its size estimate: a change set the
  estimate undercounts (a thousand methods added to a small assembly) failed the write.
- An index too wide for its two-byte column is refused instead of cut to its low bytes, which
  named another row or heap entry (`io::write_le_at_dyn` and `write_be_at_dyn` refuse such a
  value), and a heap reference the writer cannot patch fails the write rather than staying
  unpatched.
- A method body a pass replaces keeps loading the strings it loaded: its `ldstr` operands
  follow the user string heap when it moves, as the untouched bodies' do. They kept their
  input offsets, so a decrypted body read whatever string moved into its string's place.
- An assembly written back unchanged holds what it held. Method bodies at an RVA past 8 MB
  were taken for placeholders and not copied (CoreLib lost 32,370 of them); a fat method
  header no longer turns tiny, losing its maximum stack and `InitLocals`; a write that changes
  nothing keeps the debug directory and its data; and a name stored inside another string's
  bytes (a shared tail), a blob inside another blob's bytes and a user string inside another
  string's bytes keep pointing at them when the heap is rebuilt, which only cleanup used to
  arrange for names; one that names nothing is kept while it still names nothing, and the
  write is refused when the rebuilt heap would reach it.
- A row writes back the bytes it was read from: a coded index whose tag names no table keeps
  its value instead of becoming null (making it null is a change a pass makes), and
  `ConstantRaw` keeps the byte after its type (`padding`). When the blob heap is rebuilt,
  the sequence points of `MethodDebugInformation` and the imports of `ImportScope` follow it:
  the writer did not know they were blob columns.
- Heaps are read entry by entry as they are laid out: a `#Strings` entry that is not UTF-8 no
  longer ends iteration (`Strings::entries` yields every entry as bytes, and the writer copies
  them as they are), and `#US` iteration follows the length chain past zero-length padding
  and malformed entries instead of giving up after ten of them. Both had dropped every string
  after the first such entry from a written assembly.
- The user string heap is written as it was read: `ldstr ""` keeps an entry of its own instead
  of pointing at the zero-length entry at offset 0, strings holding unpaired surrogates are
  no longer rewritten through UTF-8 (and merged), and the terminal byte follows ECMA-335.
  Heaps deduplicate by content, where a 64-bit hash of it could merge two entries.
- A new or updated row's heap placeholder no longer passes for an offset. Rows were read back
  for their string references in the original layout, where a two-byte column cut a
  placeholder to its change id; once ids reached into a multi-byte name, the writer kept a
  tail of it cut mid-character, an invalid `#Strings` heap. Change ids were process-wide, so
  this hit any assembly written after about 2,000 changes in one process: each assembly now
  counts its own from 1, and a row id past what a placeholder holds is refused rather than
  wrapped. A heap offset past 8 MB is no longer taken for a row placeholder either.
- Signatures encode back to what they were read from: vararg call sites keep their extra
  arguments, local variables and type specifications their custom modifiers, and function
  pointer signatures their parameters' modifiers and by-reference flags, their generic flag
  and their calling convention, the unmanaged one (`delegate* unmanaged`) among them, which
  was written back as managed. A `calli` through an unmanaged pointer resolves its signature.
  `ELEMENT_TYPE_MODIFIER` is written as 0x40, where it was written as 0x22.

#### Analysis and code generation

- Arithmetic is typed by ECMA-335's binary numeric table; `.locals init` locals read zero;
  handler exception objects and generic instantiation members are typed; x86 stubs that read
  a register after a branch merge translate. Function pointers, `ref` parameters, returns and
  locals, a value type's `this`, and the value its own constructor builds are typed as what
  they are: every method of the corpus now lifts to SSA the verifier accepts.
- Every conversion, of every kind, is restated for the type its operand turns out to have
  (analyssa's `settle_conversions`); integer and float conversions only were before.
- Constant folding respects operand width and kind and no longer sign-extends in
  `conv.u8`/`conv.u`, folds conversions between `float32` and `float64` constants, and leaves
  an operation with a NaN operand or result to the runtime, which owns NaN payloads;
  pure-call folding needs a `Pure` or `ReadOnly` callee; inlining remaps every definition and
  use.
- Exception clauses come nested first (ECMA-335 II.19) and in the same order on every build:
  `InstructionAssembler` emitted them in a hash map's order, and `MethodBodyBuilder` now orders
  every clause it writes (`metadata::method::order_nested_first`). `MethodBodyBuilder` keeps the
  clauses the assembler builds, which it dropped; resolves labeled handlers at the offsets the
  finished code has, after branches shorten (`InstructionAssembler::finish_with_labels`); and
  writes a catch-all as a catch of `System.Object`, where it wrote a fault handler, which lets
  the exception go on. A clause moves only as far as nesting requires, so a compiler's order
  is kept.
- Generated code: `calli` passes its function pointer last, element and indirect accesses
  use the exact form for each type, values flow out of a `try` through its `finally`, and
  exception regions are laid out contiguously without silently dropping a clause.
- A call through a MethodSpec or MemberRef naming a method of the assembly is a call of that
  method in both call graphs. Class hierarchy analysis finds every override and implementation:
  of a generic base's method, of an interface method (implicitly or through a MethodImpl), and
  past an earlier overload of the name. It ends on an inheritance cycle, which overflowed the
  stack. A virtual call one of those methods could take is no longer folded or inlined. The
  call graph builds its class hierarchy once, not again for every generic method
  instantiation it names. `CallGraph::topological_order` puts callees first whether
  or not the assembly has recursion: without recursion it put callers first.
- Field types resolve by token instead of searching every type, and translation validation
  no longer grows quadratic in a method's locals: lifting, regenerating and validating the
  packer samples takes about a third of the time.
- The emulator computes with a `char` or `bool` operand as the `int32` it is on the
  evaluation stack, in arithmetic, unary operations and comparisons alike.
- `SsaFunctionBuilder` builds SSA the verifier accepts: it records each variable's uses, types
  arithmetic by its operands rather than as `int32`, and types a placeholder by its definition
  (a stated type, its operand's, the operation's own, a phi's operands').

#### Deobfuscation

- Passes remove only instructions nothing reads, and a failing pass rolls its method back
  (`EventKind::PassFailed`) instead of failing the assembly.
- A decryptor receives a string or array an earlier decryption produced, and a handle, as the
  value it is: they reached it as null. An argument the emulator cannot build fails the call
  site.
- `DeobfuscationEngine::process_ssa` ran with the default configuration instead of the
  engine's.
- Every technique with a byte transform declares it, so cleanup withholds what a failed
  transform's technique would remove. A local whose variables the passes left unused no
  longer keeps its type from cleanup, and the duplicate TypeDef repair renames only rows
  that survive cleanup, so the code generator's `<PrivateImplementationDetails>` keeps its
  name.
- Control flow unflattening keeps a value updated on a merge a rewired edge skips (ConfuserEx
  constants with x86 control flow printed zero counts).
- BitMono: embedded method tokens resolve by signature, so DotNetHook reversal no longer
  redirects 0.45 calls to the wrong methods; LocalVariableEncoding is reversed; DotNetHook's
  dummies and anti-debug injection are identified precisely.
- ConfuserEx: invalid metadata is removed and the output passes validation, the type
  scrambler's generic callees are kept, and CFG-mode constants leave no state updates or
  state type behind.
- .NET Reactor: both runtime initializers are removed, and fully protected samples get their
  resources and `typeof`s back.

#### Tests

- The suite fails where it used to pass without testing: a missing sample (every sample is
  reached through `testkit::fixture` and listed with its hash and license in
  `tests/samples/MANIFEST.toml`), a sample that fails to load, a missing .NET tool under
  `DOTSCOPE_REQUIRE_TOOLS=1` (set in CI), and a validator case that fails for another reason
  than the rule it tests. Every corpus assembly must load and every method lift
  (`full::corpus`), and a fixture malformed by design names in the manifest the error it must
  be refused with. Analysis tests verify the SSA `Method::ssa` builds, `this` and
  exception handlers included, rather than the harness's own copy. Pass tests run a pass as
  the scheduler does and verify what it leaves, and generated code is checked by running it
  against the SSA it came from, in unit tests and over every corpus method.
- No test's result depends on how busy the machine is: tests run emulation without wall-clock
  limits and order threads without sleeps. Tests run in tiers (`cargo test-quick`,
  `cargo test-full`, `make test-oracle`) with one integration test binary, and the Mono and
  .NET 10 corpus tests, ignored before, require every assembly to load. Every packer sample
  is its own test, and each sample is deobfuscated once per run however many tests check it.
- Deobfuscated packer samples are checked by what they do: each family's output must pass
  production validation and the metadata verifier where the protected sample does, and print
  under Mono exactly what the unprotected original prints (`full::runtime`), with the
  protections dotscope does not reverse declared per sample. The packer suites run the
  original's methods against their deobfuscated counterparts on fixed inputs.
- dotscope reads each assembly as System.Reflection.Metadata does: `tests/oracle/srm-dump`, a
  C# program built against the SRM the fixtures hold, writes an assembly's canonical dump from
  what Microsoft's reader reads, and the oracle tier compares it with dotscope's for every
  corpus assembly (`.winmd` included), with each fixture SRM is not the authority on declared
  with its evidence. Goldens for the fixtures tagged `srm` (`make oracle-goldens`) keep the
  comparison running without .NET tools. `metadata/sections` (a new factory family) records
  what each runtime reads at an RVA of every section layout, and dotscope is held to it.
- Fuzzing covers every parser and codec, the PE layer, the writer's round trip, the IL to
  SSA to IL pipeline and bounded emulation and deobfuscation, with seed corpora (`make fuzz`;
  `testkit::fuzz` holds the entry points). CI runs no fuzzer: every input a fuzzer once failed
  on is committed under `tests/samples/fuzz-regressions/<target>/` and replayed through its
  target (`fuzz_regressions`), with what it allocates bounded. Benchmarks fail when their
  work does, and `benches/workloads.rs` measures the writer, SSA lifting, the passes, code
  generation, emulation, project loading and the call graph, time and memory both. The sizes
  of the hot types are pinned at compile time.

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
