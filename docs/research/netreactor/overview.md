# .NET Reactor Protection Analysis

Research documentation for .NET Reactor 7.5.0 protections, based on:
- Reverse engineering of 18 test samples using dotscope (see per-protection docs below)
- NETReactorSlayer (NRS) source code analysis for gap assessment
- Official .NET Reactor documentation (bundled help files)

## Per-Protection Documentation

| Protection | Document | Sample | Key Finding |
|-----------|----------|--------|-------------|
| NecroBit (Stage 1) | [necrobit.md](necrobit.md) | `reactor_necrobit.exe` (70KB, 258 methods) | All method bodies replaced with stubs (`nop;nop;ret`), restored at runtime via `Marshal.Copy`. .cctor injected into every type. Custom XOR/shift cipher + MD5-style padding. 667-case CFF-protected init. |
| Control flow (Stage 2) | [controlflow.md](controlflow.md) | `reactor_controlflow.exe` / `_max.exe` | `<Module>{GUID}` type with 126 Int32 instance fields as opaque predicates. Switch-based CFF dispatcher. Level 5: 3-7 predicates/method. Level 9: 4-7 predicates + more fake states. |
| Anti-tamper (Stage 3) | [anti-tamper.md](anti-tamper.md) | `reactor_antitamp.exe` (49KB, 214 methods) | .cctor injected into ALL types calling CFF-protected init. AES-256 via RijndaelManaged. `Interlocked.Exchange`/`CompareExchange` for thread-safe state. GUID-annotated marker types. |
| String encryption (Stage 6) | [strings.md](strings.md) | `reactor_strings.exe` (60KB, 175 methods) | `ldstr` -> arithmetic + per-call-site XOR + `call decryptor(int32)`. ~90 XOR key fields in GUID container. TEA/XTEA cipher + AES. #US heap shrinks. `Hashtable` cache with `Monitor` locking. |
| Resource encryption (Stage 7) | [resources.md](resources.md) | `reactor_resources.exe` (54KB, 185 methods) | Call-site rewrite: `GetManifestResourceStream` replaced with injected resolver. Lazy init via 358-case CFF method. Native memory utility type. AES decryption. |
| Anti strong name (Stage 12) | [anti-strong.md](anti-strong.md) | `reactor_antistrong.exe` (36KB, 152 methods) | Hand-written MD5 (all 4 round functions). `DynamicMethod` + `ILGenerator` patches verification methods at runtime. Multi-fallback crypto provider detection. |
| Symbol renaming (Stage 15) | [renaming.md](renaming.md) | `reactor_obfuscation.exe` (18KB, 46 methods) | Standard mode: 18-char random namespace, 18-char type, 9-char method names. `.ctor`/`.cctor` preserved. Constant table removed. |
| SuppressIldasm | [suppressildasm.md](suppressildasm.md) | `reactor_suppressildasm.exe` (20KB, 55 methods) | Duplicate Assembly table row (breaks ildasm). Out-of-bounds GUID/blob refs. Empty TypeRef name. `br.s +5` anti-disassembly prefixes. |
| Pre-JIT | [prejit.md](prejit.md) | `reactor_prejit.exe` (19KB, 55 methods) | Native-level only — no managed metadata impact. Identical to compression at metadata level. |
| Compression | [compression.md](compression.md) | `reactor_compression.exe` (19KB, 55 methods) | Native-level only — transparent after loader decompression. Identical to pre-JIT at metadata level. |
| Code virtualization | [virtualization.md](virtualization.md) | `reactor_virtualization.exe` (125KB, 851 methods) | Full VM: 176-case opcode dispatcher (4,781 lines), 4 polymorphic value types (88-104 methods each), stack-based execution, encrypted bytecode with custom 6-bit encoding. 79 injected types. |
| Shared infrastructure | [shared-infrastructure.md](shared-infrastructure.md) | All samples | Trial guard (`m8DE92F4E*`), delegate proxy (`AsG4wKEPrjKTCY31dc`), license check (`UWxvxUSU2ZrCqT9K8B`). Stable type names across all builds of same NR version. |
| Encrypted resource | [encrypted-resource.md](encrypted-resource.md) | Multiple | AES-256 via `RijndaelManaged` + custom TEA/XTEA cipher. MD5-style Merkle-Damgard padding for key derivation. Shared across NecroBit, strings, resources, anti-tamper, anti-strong, VM. |
| Full combination | [full-protection.md](full-protection.md) | `reactor_full.exe` (143KB, 381 methods) | 10-step layering order. NecroBit applied last (must reverse first). ~346 injected methods total. Protection interactions documented. |

## Protection Inventory (NRS Stage Order)

NRS implements 15 sequential deobfuscation stages, each targeting a specific .NET Reactor
protection. The stages run in strict order — earlier stages (especially MethodDecrypter)
must succeed for later stages to be effective.

| # | Stage | Protection | Category |
|---|---|---|---|
| 1 | MethodDecrypter | Method body encryption (NecroBit) | Byte-level |
| 2 | ControlFlowDeobfuscator | Arithmetic opaque constants via fields | Structure |
| 3 | AntiManipulationPatcher | Anti-tamper + anti-debug | Neutralization |
| 4 | MethodInliner | Method proxy/stub indirection | Call |
| 5 | ProxyCallFixer | Delegate-based call proxying | Call |
| 6 | StringDecrypter | String encryption (AES) | Value |
| 7 | ResourceResolver | Encrypted resource embedding | Protection |
| 8 | AssemblyResolver | Assembly embedding (DNR) | Protection |
| 9 | CosturaDumper | Costura.Fody merging | Protection |
| 10 | TokenDeobfuscator | Metadata token obfuscation | Metadata |
| 11 | BooleanDecrypter | Boolean constant encryption | Value |
| 12 | StrongNamePatcher | Strong name verification | Neutralization |
| 13 | TypeRestorer | Type obfuscation (Object placeholders) | Metadata |
| 14 | Cleaner | Post-processing cleanup | Cleanup |
| 15 | SymbolRenamer | Name obfuscation | Metadata |


## Per-Protection Technical Detail

### Stage 1 — MethodDecrypter (NecroBit)

**What it protects**: Encrypts method bodies so they cannot be read by disassemblers or
decompilers. The most critical protection — without decryption, all other stages are useless.

**Detection**:
- Searches for methods with native signatures:
  - `UInt32(IntPtr, IntPtr, IntPtr, UInt32, IntPtr, UInt32&)`
  - `UInt32(UInt64&, IntPtr, IntPtr, UInt32, IntPtr&, UInt32&)`
- Checks `<Module>.cctor` for calls to these native helpers.

**Encryption scheme**: XOR-decrypts an embedded resource using a key extracted from
`ldind_I8` + `ldc_I8`/`ldc_I4` patterns in the decryptor method body.

**Data format**: The decrypted resource contains:
- Patch count and mode flags
- Per-method entries in one of two modes:
  - **Mode 0/1** (RVA-based): Writes decrypted bodies to PE sections at specific RVAs
  - **Mode 2+** (DNR-specific): Method table indexing with DNR format entries
- **.NET 4.5+ variant**: Multiplies sizes by 4

**Helpers**: `FindBinaryReaderMethod()`, `IsNewer45Decryption()`, `IsUsingRva()`,
`XorEncrypt()`, `DumpedMethodsRestorer`.


### Stage 2 — ControlFlowDeobfuscator

**What it protects**: Replaces integer constants with field lookups from an obfuscator-
generated type, creating opaque arithmetic expressions.

**Detection (static)**:
- Searches for sealed types with 100+ static/instance `System.Int32` fields
- Looks for initialization patterns: `ldc.i4 <value>` → `stsfld/stfld <field>`

**Detection (dynamic)**: Falls back to reflection if static analysis fails.

**Deobfuscation**: Extracts field values, replaces `ldsfld`/`ldfld` references with
`ldc.i4 <resolved_value>`. Marks obfuscator type for removal.


### Stage 3 — AntiManipulationPatcher

**What it protects**: Injects code that terminates the process if tampering or debugging
is detected at runtime.

**Detection**: Searches method string literals for:
- `"is tampered"` (anti-tamper check)
- `"Debugger Detected"` (anti-debug check)

**Deobfuscation**: Replaces entire method body with a single `ret` instruction.


### Stage 4 — MethodInliner

**What it protects**: Replaces direct calls with indirection through trivial proxy methods.

**Detection patterns**:
1. `ldarg_X` → `call/callvirt/newobj` → `ret` (call forwarding)
2. `ldarg_X` → `ldfld` → `ret` (field accessor)
3. `ldc.i4` → `call/callvirt/newobj` → `ret` (constant-arg forwarding)

**Deobfuscation**: Extracts proxy method instructions, inserts at call site, replaces
the `call` with `nop`. Removes proxy methods.


### Stage 5 — ProxyCallFixer

**What it protects**: Hides method references behind delegate indirection, with the
mapping stored in an encrypted binary resource.

**Detection**:
- Finds delegate types in empty namespace deriving from `System.Delegate`
- Examines `.cctor` for methods called with `RuntimeTypeHandle` parameter
- Identifies the most frequently called method (the call resolver)
- Validates it as an `EncryptedResource` decrypter

**Encryption scheme**: Encrypted binary resource containing pairs of `int32`:
- Key = obfuscated token
- Value = real method token
- Bit `0x40000000` in the value distinguishes `callvirt` from `call`

**Deobfuscation**: Decrypts resource, scans for `ldsfld <proxy_delegate>` →
`call <resolver>`, replaces with direct call to the actual method.


### Stage 6 — StringDecrypter

**What it protects**: Encrypts all string literals with AES, replacing them with calls to
a decryptor method.

**Detection**:
- Searches for static methods with signature `System.String(System.Int32)`
- Validates via EncryptedResource infrastructure (CryptoStream/ICryptoTransform patterns)
- Extracts 32-byte key and 16-byte IV from `ldtoken` on `FieldDef` with `InitialValue`

**Two versions**:
- **V37**: Key/IV from field `InitialValue`, string offsets stored in resource
- **V38**: Key/IV from field `InitialValue`, uses RVA-based reading with IntPtr

**Encryption**: AES-CBC with PKCS7 padding. If `PublicKeyToken` exists, overwrites
odd-indexed IV bytes with the token bytes.

**NRS dynamic fallback**: Uses Harmony patches to hijack `StackFrame.GetMethod()` and
invokes string decryption via reflection at runtime.


### Stage 7 — ResourceResolver

**What it protects**: Embeds assembly resources in encrypted form, resolved at runtime
via `AssemblyResolve` event handlers.

**Detection**:
- Searches for types with 3–4 fields: `System.Boolean` (1–2×), `System.Object` (optional),
  `System.String[]` or `System.Reflection.Assembly` (optional)
- Finds method with signature `(System.Object, System.ResolveEventArgs)` or
  `(System.Object, System.Object)`
- Validates as `Assembly.ResolveEventArgs` handler (checks for `"add_AssemblyResolve"`)
- Confirms EncryptedResource decrypter

**Deobfuscation**: Decrypts resource via EncryptedResource, decompresses with
QuickLZ or Deflate (zlib), extracts embedded assemblies.


### Stage 8 — AssemblyResolver (DNR)

**What it protects**: Embeds dependent assemblies in encrypted resources, resolved
dynamically via `AssemblyResolve` handlers using a hashtable cache.

**Detection**:
- Finds types with 2–4 fields: `System.Boolean` (1–2×),
  `System.Collections.Hashtable`/`System.Object` (1–2×)
- Locates static `System.Void()` method calling `add_AssemblyResolve`
- Finds resolver method returning `System.Reflection.Assembly` with local types
  including BinaryReader, Stream, Hashtable

**Deobfuscation**: Extracts resource name from string literals, decrypts via
EncryptedResource, writes extracted assemblies to disk.


### Stage 9 — CosturaDumper

**What it protects**: Costura.Fody-merged assemblies (separate from .NET Reactor, but
commonly combined).

**Detection**: Scans for `"costura.metadata"` resource and resources matching
`"*.compressed"` pattern.

**Deobfuscation**: Decompresses `.compressed` resources using DEFLATE, writes assemblies
to disk, removes `"Costura.AssemblyLoader::Attach()"` call from `.cctor`.


### Stage 10 — TokenDeobfuscator

**What it protects**: Replaces `ldtoken` instructions with obfuscated integer constants
resolved through helper methods at runtime.

**Detection**:
- Finds types with no properties/events, at least one field, and a `System.ModuleHandle`
  field (marker)
- Identifies two resolver methods:
  - `RuntimeTypeHandle(System.Int32)` (TypeDef resolver)
  - `RuntimeFieldHandle(System.Int32)` (FieldDef resolver)

**Deobfuscation**: Scans for `ldc.i4 <obfuscated>` → `call <resolver>`, resolves
tokens via `Module.ResolveToken()`, replaces with `ldtoken <real_token>`.


### Stage 11 — BooleanDecrypter

**What it protects**: Encrypts boolean constants in an embedded resource, replacing them
with calls to a decryptor method.

**Detection**:
- Searches for non-nested types with method signature `System.Boolean(System.Int32)`
- Validates via `EncryptedResource.IsKnownDecrypter()`

**Data format**: Decrypted resource is a byte array. Offset lookup: byte value `0x80` =
`true`, anything else = `false`.

**Deobfuscation**: Scans for `ldc.i4 <index>` → `call <bool_decrypter>`, replaces with
`ldc.i4.1`/`ldc.i4.0`.


### Stage 12 — StrongNamePatcher

**What it protects**: Injects strong name signature verification to detect assembly
modification.

**Detection**:
- Finds static method with signature `Object/String(Object/String, Object/String)`
  requiring crypto local types (MD5, CryptoStream, Rijndael or SymmetricAlgorithm)
- Detection pattern in callers: `ldtoken <type>` → `GetTypeFromHandle()` →
  `get_Assembly()` → `GetName()` → `GetPublicKeyToken()` → `ToBase64String()` →
  `ldstr <expected_key>` → `call <verify>` → `ldstr <error>` → conditional branch

**Deobfuscation**: Forces jump to success path, removes exception handlers.


### Stage 13 — TypeRestorer

**What it protects**: Replaces real parameter/return types with `System.Object` to
hinder static analysis.

**Technique**: Uses de4dot's `TypesRestorerBase` to infer types from method signatures
and usage patterns. Rejects value types and `System.Object` placeholders.


### Stage 14 — Cleaner

**Post-processing**:
- Removes empty methods (only `ret`)
- Fixes entrypoint if located in `<PrivateImplementationDetails>`
- Fixes CLR metadata version (V1.1 → V2.0)
- Removes obfuscator types, resources, marked methods/fields
- Removes calls to infrastructure methods
- Strips junk (dummy types with 10+ calls, DNR trial methods with
  "unregistered version" strings)
- Strips attributes: `DebuggerHidden`, `DebuggerStepThrough`,
  `DebuggerNonUserCode`, `MethodImpl(0)`, `MethodImpl(NoInlining)`
- Removes empty `.cctor`s


### Stage 15 — SymbolRenamer

**Protection**: Renames all symbols (namespaces, types, methods, fields, properties,
events, method args, generic params) to non-meaningful names.

**Technique**: Uses de4dot Renamer infrastructure with configurable flags per symbol kind.


## EncryptedResource — Shared Decryption Infrastructure

NRS's most important helper (`EncryptedResource.cs`, ~1320 lines). Most protections
use it for encrypted resource access.

**Four decrypter variants**:

| Variant | Detection | Scheme |
|---|---|---|
| DecrypterV1 (Classic AES) | CryptoStream + ICryptoTransform locals | AES-CBC + PKCS7. 32-byte key, 16-byte IV from field `InitialValue`. IV may be reversed or mixed with `PublicKeyToken`. |
| DecrypterV2 (Rolling XOR) | Int32 + Byte[] locals (simpler pattern) | XOR with rolling sum. Old sub-variant: `sum = f(sum_prev ^ key)`. New sub-variant: `sum = (sum_prev + key) + magic(sum_prev + key)`. |
| DecrypterV3 | Variant of V2, minimal pattern | Rolling XOR variant |
| DecrypterV4 | More sophisticated detection | Extended pattern matching |

**Key discovery**: `GetDecryptionKey()` finds 32-byte field via `ArrayFinder`.
`GetDecryptionIV()` finds 16-byte field with checks for reversing and
`PublicKeyToken` mixing.

**Supported .NET Reactor versions**: V3.7, V3.8+, V6.9, V6.X.

**Code Virtualization**: Detected (multiple switch statements + 15+ `ldtoken`
instructions) but NOT removed — out of scope for NRS.


## Gap Analysis

### Coverage Summary

| Status | Count | Stages |
|---|---|---|
| Covered | 3 | 4, 14, 15 |
| Partially Covered | 6 | 2, 3, 5, 6, 7, 11 |
| Missing | 6 | 1, 8, 9, 10, 12, 13 |

### Detailed Gap Table

| # | Protection | Status | dotscope Technique(s) | Gap Description |
|---|---|---|---|---|
| 1 | MethodDecrypter (NecroBit) | **Missing** | — | No equivalent. Requires XOR resource decryption + PE section patching + DumpedMethods restoration. ConfuserEx anti-tamper (`confuserex.tamper`) decrypts method bodies at byte level but the format is completely different. |
| 2 | ControlFlowDeobfuscator | **Partial** | `generic.opaquefields`, `OpaqueFieldPredicatePass` | dotscope resolves static fields via `.cctor` emulation, but NR uses sealed types with 100+ fields including both static AND instance fields. dotscope's pass is focused on field-chain predicates (`LoadStaticField → LoadField → Branch`), not bulk arithmetic substitution across all methods. Instance field resolution is not supported. |
| 3 | AntiManipulationPatcher | **Partial** | `generic.debug`, `generic.dump`, `NeutralizationPass` | dotscope detects API-based patterns (`Debugger.IsAttached`, `VirtualProtect`, etc.) but NR uses string-based detection (`"is tampered"`, `"Debugger Detected"`). The neutralization infrastructure works but the detection signatures don't match NR's patterns. |
| 4 | MethodInliner | **Covered** | `InliningPass` (compiler), `confuserex.proxy` | dotscope's inlining pass handles trivial call-through stubs. The compiler's `InliningPass` already devirtualizes small proxy methods. |
| 5 | ProxyCallFixer | **Partial** | `generic.delegates`, `DelegateProxyResolutionPass`, `confuserex.proxy` | dotscope resolves delegate proxies via `.cctor` emulation and SSA def-use analysis, but NR's proxy format is NR-specific: encrypted binary resource containing token pairs with bit `0x40000000` for callvirt. This requires NR-specific resource decryption and token pair parsing. |
| 6 | StringDecrypter | **Partial** | `generic.strings`, `DecryptionPass` | dotscope detects `string(int32)` signatures and emulates decryptors. The emulation approach should work IF the emulator can handle NR's decryptor method. However, NR has version-specific (V37/V38) key/IV discovery patterns and PublicKeyToken IV mixing that may require NR-specific detection to locate the correct decryptor and resource. The `DecryptionPass` with emulation would handle actual decryption once the decryptor method is identified. |
| 7 | ResourceResolver | **Partial** | `confuserex.resources` | dotscope handles ConfuserEx resource protection (LZMA + XOR/block-cipher), but NR uses EncryptedResource (AES/XOR) + QuickLZ/Deflate. The ConfuserEx technique is not generic — an NR-specific implementation would be needed for resource name discovery, decryption variant selection, and decompression (especially QuickLZ). |
| 8 | AssemblyResolver (DNR) | **Missing** | — | No assembly extraction/dumping capability. NR embeds dependent assemblies in encrypted resources resolved via `AssemblyResolve` handlers. Requires resource decryption + assembly extraction + output to disk. |
| 9 | CosturaDumper | **Missing** | — | No Costura.Fody-specific handling. Requires scanning for `"costura.metadata"` resource, DEFLATE decompression, and `.cctor` patching. Separate from NR but commonly combined. |
| 10 | TokenDeobfuscator | **Missing** | — | No token deobfuscation. NR replaces `ldtoken` with `ldc.i4 <obfuscated>` + `call <resolver>`. Requires pattern matching (`ModuleHandle` marker field) and token resolution via `Module.ResolveToken()`. |
| 11 | BooleanDecrypter | **Partial** | `generic.constants`, `DecryptionPass` | dotscope detects `T(int32)` constant decryptors and emulates them. The emulation approach may work for NR booleans, but NR's specific format (byte array with `0x80` marker) might be faster to handle via static resource decryption rather than per-callsite emulation. |
| 12 | StrongNamePatcher | **Missing** | — | No strong name verification removal. NR inserts signature verification flows with crypto-based validation that need specific pattern matching (MD5/Rijndael locals) and branch forcing. |
| 13 | TypeRestorer | **Missing** | — | No type restoration from `System.Object` placeholders. Requires cross-method type inference based on usage patterns (de4dot's `TypesRestorerBase`). This is a deep analysis pass, not simple pattern matching. |
| 14 | Cleaner | **Covered** | `execute_cleanup`, `NeutralizationPass`, DCE | dotscope's cleanup pipeline (orphan removal, heap compaction, PE generation) and neutralization pass cover the same ground. Attribute stripping and dead `.cctor` removal are already handled. |
| 15 | SymbolRenamer | **Covered** | `renamer/` module | dotscope's cleanup renames obfuscated identifiers to short sequential names (`CleanupConfig::rename_obfuscated_names`). |


### Detailed Gap Descriptions

#### NecroBit Method Decryption (Stage 1) — Critical, Blocks Everything

This is the highest-priority gap. Without method body decryption, every subsequent stage
operates on encrypted bytecode and produces no results.

**What's needed**:
- Native method signature detection (two specific signatures)
- XOR key extraction from `ldind_I8` + `ldc_I8`/`ldc_I4` patterns
- Encrypted resource location and XOR decryption
- Method body restoration in two modes:
  - RVA-based: patch decrypted bodies into PE sections
  - DNR-format: method table indexing with per-entry restoration
- .NET 4.5+ size multiplier detection

**Closest existing code**: `confuserex.tamper` performs byte-level method body decryption
from a PE section, including XOR key emulation. The infrastructure for byte-level
transforms and PE patching exists, but the format parsing is completely different.

**Implementation approach**: New byte-level technique `netreactor.necrobit` with
`detect()` searching for the native helper signatures and `byte_transform()` performing
XOR resource decryption + body restoration. Could leverage existing
`CilAssembly::patch_method_body()` for the actual patching.

#### NR-Specific Proxy Call Resolution (Stage 5)

**What's needed**:
- Delegate type identification in empty namespace
- EncryptedResource decryption (AES or rolling XOR, version-dependent)
- Token pair parsing with `0x40000000` callvirt bit
- Call site replacement: `ldsfld <proxy>` + `call <resolver>` → direct call

**Closest existing code**: `generic.delegates` + `DelegateProxyResolutionPass` handle
delegate-based proxying via emulation. The NR format is structurally different (encrypted
resource lookup vs. runtime delegate binding), so a dedicated technique is needed.

#### NR-Specific String Decryption (Stage 6)

**What's needed**:
- Version-aware decryptor detection (V37 vs V38 key/IV discovery)
- AES key/IV extraction from field `InitialValue`
- PublicKeyToken IV byte mixing
- EncryptedResource decryption (4 decrypter variants)

**Closest existing code**: `generic.strings` with `DecryptionPass` can emulate
NR string decryptors if they're detected. The emulation engine already has AES BCL
support (`emulation/runtime/bcl/crypto/symmetric.rs`). An NR-specific detection technique
could identify the decryptor method and register it with `DecryptionPass`, leveraging
existing emulation rather than reimplementing decryption.

#### Token Deobfuscation (Stage 10)

**What's needed**:
- `ModuleHandle` marker field detection
- Resolver method identification (`RuntimeTypeHandle(Int32)`, `RuntimeFieldHandle(Int32)`)
- Pattern matching: `ldc.i4 <obfuscated>` → `call <resolver>` → replace with
  `ldtoken <real_token>`
- Token resolution (can be done statically via metadata tables)

**No existing equivalent**. This is a new pattern not seen in other supported obfuscators.
Could be implemented as an SSA pass that traces `Call` operands back to constant arguments,
resolves tokens via `CilObject::resolve_token()`, and replaces with `LoadToken`.

#### Strong Name Verification Removal (Stage 12)

**What's needed**:
- Detection: method with crypto locals (MD5/Rijndael/SymmetricAlgorithm) and
  specific call chain pattern (GetPublicKeyToken → ToBase64String → compare)
- Deobfuscation: force conditional branch to success path

**Closest existing code**: `NeutralizationPass` can remove method bodies, and the
`generic.debug`/`generic.dump` detection patterns show how API-based detection works.
A new detection signature combined with branch forcing would suffice.

#### Type Restoration (Stage 13)

**What's needed**:
- Cross-method type inference engine
- Usage-based type narrowing (method calls, field stores, casts)
- Signature patching for parameters and return types

**No existing equivalent**. This is architecturally complex — it requires whole-program
type analysis. de4dot's `TypesRestorerBase` performs iterative fixpoint analysis across
all methods. This could leverage dotscope's SSA type system but would be a significant
new analysis pass.

#### Embedded Assembly Extraction (Stages 7, 8, 9)

Three related gaps around extracting embedded assemblies:

- **ResourceResolver (7)**: NR-specific EncryptedResource + QuickLZ/Deflate
- **AssemblyResolver (8)**: DNR format with hashtable-cached AssemblyResolve
- **CosturaDumper (9)**: Costura.Fody DEFLATE-compressed resources

All three require the ability to output extracted assemblies as separate files. dotscope
currently processes a single assembly — multi-assembly output would be a new capability.
`confuserex.resources` is the closest existing code (encrypted resource extraction + LZMA
decompression) but targets a different format.


## dotscope Infrastructure Leverage Points

Several existing dotscope subsystems are directly applicable to NR support:

| Subsystem | Applicable To | How |
|---|---|---|
| Byte-level transform phase | NecroBit (1) | Same phase as `confuserex.tamper` — XOR decryption + PE patching |
| `OpaqueFieldPredicatePass` + emulation | ControlFlow (2) | Extend to handle instance fields and bulk field types with 100+ fields |
| `NeutralizationPass` | AntiManipulation (3), StrongName (12) | Already handles surgical method neutralization; add NR-specific detection patterns |
| `InliningPass` (compiler) | MethodInliner (4) | Already covers trivial proxy stubs |
| `DelegateProxyResolutionPass` + emulation | ProxyCallFixer (5) | Emulation-based approach works but NR uses encrypted resource, not runtime binding |
| `DecryptionPass` + emulation engine | Strings (6), Booleans (11) | Register NR decryptors; AES BCL support already implemented |
| `confuserex.resources` pattern | ResourceResolver (7) | Same architecture (detect handler, decrypt resource, extract), different format |
| `generic.strings` detection | Strings (6) | `string(int32)` signature match already covers NR decryptor shape |
| State machine framework | ProxyCallFixer (5), Strings (6) | `statemachine.rs` designed for cross-obfuscator reuse |
| Cleanup pipeline | Cleaner (14) | Already comprehensive |
| Renamer module | SymbolRenamer (15) | Already comprehensive |


## Priority Assessment

### Tier 1 — Blocks Everything (must be first)

**Stage 1: NecroBit Method Decryption**
- Without this, all other stages operate on encrypted bytecode
- Byte-level technique with XOR resource decryption + PE body patching
- Moderate complexity; can reference `confuserex.tamper` for the byte-transform pattern
- Estimated scope: ~500–700 lines (detection + 2 restoration modes + .NET 4.5 variant)

### Tier 2 — Core Value Recovery (highest user impact)

**Stage 6: String Decryption**
- Critical for readability
- Emulation-based approach via `DecryptionPass` is likely sufficient
- NR-specific detection technique to identify decryptor + register with shared pass
- May work partially via `generic.strings` without any NR-specific code
- Estimated scope: ~200–400 lines (detection + EncryptedResource key/IV extraction)

**Stage 5: Proxy Call Resolution**
- Required for clean call graphs and further analysis
- NR-specific encrypted resource format (token pairs with callvirt bit)
- Estimated scope: ~300–500 lines (detection + resource decryption + token mapping)

**Stage 10: Token Deobfuscation**
- Affects type/field resolution throughout the assembly
- Clean SSA-level pass: pattern match + token resolve + replace
- Estimated scope: ~200–300 lines

### Tier 3 — Important Improvements

**Stage 2: Opaque Constants**
- Extend `OpaqueFieldPredicatePass` for NR-style bulk field types
- Needs instance field support and higher field-count thresholds
- Estimated scope: ~150–250 lines (detection + pass extension)

**Stage 11: Boolean Decryption**
- May already work via `generic.constants` + emulation
- NR-specific static decryption (byte array with `0x80` marker) is faster
- Estimated scope: ~100–200 lines

**Stages 7/8: Resource + Assembly Extraction**
- Important for complete deobfuscation of packed assemblies
- Requires EncryptedResource infrastructure (shared with stages 5, 6, 11)
- QuickLZ decompression is a new dependency
- Estimated scope: ~400–600 lines combined

### Tier 4 — Cleanup and Polish

**Stage 3: Anti-Manipulation** — Add string-based detection patterns to existing
`generic.debug`/`generic.dump`. Minimal effort (~50 lines).

**Stage 12: Strong Name Verification** — New detection + branch forcing. Moderate effort
(~150–200 lines).

**Stage 9: Costura.Fody** — Independent of NR, useful as generic capability. DEFLATE
decompression + resource scanning (~200–300 lines).

**Stage 13: Type Restoration** — Architecturally complex whole-program analysis.
Lowest priority; benefits are incremental once other stages succeed. Significant effort
(~1000+ lines).


## EncryptedResource — Shared Implementation Opportunity

Stages 5, 6, 7, 8, and 11 all use EncryptedResource for decryption. Implementing this
as a shared utility unlocks five protections at once.

**Required components**:
1. Decrypter variant detection (V1–V4 pattern matching on method locals)
2. Key discovery (32-byte field via `ArrayFinder` on `InitialValue`)
3. IV discovery (16-byte field, optional reversal, PublicKeyToken mixing)
4. AES-CBC decryption (already in emulation BCL)
5. Rolling XOR decryption (V2/V3/V4 variants)
6. Resource location (by name or by method reference)

This could be implemented as a shared helper in `deobfuscation/techniques/netreactor/`
and used by all NR techniques that need encrypted resource access.

**Estimated scope**: ~400–600 lines for the shared EncryptedResource infrastructure.


## Implementation Ordering

Recommended sequence considering dependencies and shared infrastructure:

```
1. EncryptedResource shared infrastructure (unlocks 5/6/7/8/11)
2. NecroBit method decryption (byte-level, must be first in pipeline)
3. NR detection signature + registry entry
4. String decryption (highest user-visible impact after body decryption)
5. Proxy call resolution (clean call graphs)
6. Token deobfuscation (clean metadata references)
7. Opaque constants (extend existing pass)
8. Boolean decryption (extend existing pass or static)
9. Resource/assembly extraction (7/8 together)
10. Anti-manipulation patterns (extend existing detection)
11. Strong name removal (new detection)
12. Costura.Fody (independent, generic utility)
13. Type restoration (long-term, architecturally complex)
```

## Code Virtualization

NRS detects but does NOT handle .NET Reactor's code virtualization (multiple switch
statements + 15+ `ldtoken` instructions). This is out of scope for NRS and would be
out of scope for initial dotscope NR support as well. Code virtualization is a
fundamentally harder problem requiring VM opcode reverse engineering per sample.
See [vm_devirtualization.md](../design/vm_devirtualization.md) for the generic VM
devirtualization design that will eventually cover .NET Reactor VM alongside KoiVM
and EazVM.


## CLI Reference

.NET Reactor console CLI (`dotNET_Reactor.Console.exe`) — extracted from the
[official documentation](https://www.eziriz.com/help/command_line_parameters/).

### Installation

- **Chocolatey**: `choco install dotnetreactor` (latest: 7.5.0 as of 2026-04)
- **Install path**: `C:\Program Files (x86)\Eziriz\.NET Reactor\`
- **Environment variables**: `DOTNET_REACTOR` (install dir), `DOTNET_REACTOR_CMD` (console exe)
- **Silent install**: InnoSetup, `/VERYSILENT /SUPPRESSMSGBOXES`

### Trial Behavior

- Trial is indefinite (nag dialog on startup)
- Protected output has 14-day execution expiry (irrelevant for structural analysis)
- License state stored in registry (`HKCU\Software\Eziriz\` or similar)
- Uninstall does not necessarily reset trial state; use VM snapshots for version testing

### Protection Flags

All boolean flags accept `1` (enable) or `0` (disable).

| Flag | Protection | Category |
|------|-----------|----------|
| `-necrobit` | NecroBit method body encryption | Byte-level |
| `-necrobit_comp` | NecroBit reflection compatibility mode | Byte-level |
| `-stringencryption` | String encryption (AES) | Value |
| `-control_flow_obfuscation` | Control flow obfuscation | Structure |
| `-flow_level 1-9` | Control flow intensity (1=lowest, 9=strongest) | Structure |
| `-antitamp` | Anti-tamper detection | Neutralization |
| `-resourceencryption` | Resource encryption | Protection |
| `-resourcecompression` | Resource compression (`nocompression`/`fastest`/`fast`/`normal`/`good`/`max`) | Protection |
| `-obfuscation` | Symbol renaming (non-public) | Metadata |
| `-obfuscate_public_types` | Symbol renaming (all types/members) | Metadata |
| `-suppressildasm` | SuppressIldasm attribute | Metadata |
| `-antistrong` | Anti strong name removal | Neutralization |
| `-nativeexe` | Native x86 EXE stub generation | Byte-level |
| `-prejit` | Pre-JIT native code conversion | Byte-level |
| `-compression` | Compress output file | Protection |
| `-embed` | Pack additional assemblies | Protection |
| `-merge` | Merge multiple assemblies | Protection |
| `-internalization` | Convert public types to internal | Metadata |

### General Flags

| Flag | Description |
|------|-----------|
| `-file <path>` | Input assembly path |
| `-targetfile <path>` | Output file path |
| `-project <path>` | .nrproj project file |
| `-q` / `-quiet` | Suppress success messages |
| `-licensed` | Require full license (fail if trial) |
| `-logfile <path>` | Event/error log file |
| `-snkeypair <path>` | Strong name key pair (.snk/.pfx) |
| `-regularexpressions <regex>` | Exclusion patterns |

### Project File Format

`.nrproj` files are XML:
```xml
<Reactor_Project ProjectFormat="2">
  <Main_Assembly>Assembly.dll</Main_Assembly>
  <General_Settings>
    <Automatic_Exception_Handling>true</Automatic_Exception_Handling>
  </General_Settings>
  <Protection_Settings>
    <Anti_ILDASM>true</Anti_ILDASM>
  </Protection_Settings>
</Reactor_Project>
```

### Sample Generation

Test samples use CLI flags directly (no .nrproj files). Variants cover each protection
in isolation and key combinations. See `tests/samples/packers/netreactor/generate.ps1`.

| Sample | Protections | Purpose |
|--------|-----------|---------|
| `original.exe` | None | Unobfuscated baseline |
| `reactor_necrobit.exe` | NecroBit | Method body encryption (Stage 1, blocks everything) |
| `reactor_strings.exe` | String encryption | AES string encryption (Stage 6) |
| `reactor_controlflow.exe` | CFF level 5 | Opaque field constants (Stage 2) |
| `reactor_controlflow_max.exe` | CFF level 9 | Maximum CFF intensity |
| `reactor_resources.exe` | Resource encryption | Encrypted resources (Stage 7) |
| `reactor_antitamp.exe` | Anti-tamper | Tamper detection (Stage 3) |
| `reactor_obfuscation.exe` | Symbol renaming | Non-public renaming (Stage 15) |
| `reactor_suppressildasm.exe` | SuppressIldasm | Anti-ILDasm attribute |
| `reactor_necrobit_strings.exe` | NecroBit + strings | Two-protection combination |
| `reactor_necrobit_strings_cff.exe` | NecroBit + strings + CFF | Three-protection combination |
| `reactor_full.exe` | All protections | Full protection profile |
| `reactor_nativeexe.exe` | NecroBit + native EXE | Native x86 stub edge case |
