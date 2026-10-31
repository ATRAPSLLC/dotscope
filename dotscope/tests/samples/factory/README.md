# Test-sample factory

Generates dotscope's protector samples and metadata fixtures on Linux, in Docker, and
checks every sample against the runtimes it targets.

```sh
./build.sh --all                     # every family, then the oracle
./build.sh confuserex oracle         # some families
./build.sh --force bitmono           # regenerate outputs that already exist
```

The image (`Dockerfile`) holds Wine with the .NET Framework 4.8, the Linux .NET SDK and
Mono. `build.sh` mounts `tests/samples` and runs `generate.sh` in it; a family skips any
output that already exists unless `--force` is given. Downloads are pinned by sha256 and
cached in the `dotscope-samples-cache` volume.

.NET Reactor is commercial and runs only on a licensed Windows install: its samples come
from `../packers/regenerate.sh` instead.

New or regenerated outputs change `tests/samples/MANIFEST.toml`'s hashes: refresh it with
`DOTSCOPE_WRITE_MANIFEST=1 cargo test --profile ci-test -p dotscope --lib -- testkit::fixtures`.

## Families

| Family | Output | How |
|---|---|---|
| `confuserex` | `packers/confuserex/1.6.0/<config>.exe` | ConfuserEx 1.6.0 release CLI under Wine, one sample per `.crproj` |
| `bitmono` | `packers/bitmono/{0.39.0,0.45.0}/<config>.exe` | BitMono's `net462` CLI built from the tag, under Wine, one sample per `.json` |
| `obfuscar` | `packers/obfuscar/2.2.50/<config>.exe` | the .NET Framework `Obfuscar.Console.exe` from the NuGet package, under Wine |
| `jiejie` | `packers/jiejie/source/<variant>.exe` | JIEJIE.NET d28aa56 built for net48, under Wine (see below) |
| `variants` | `metadata/layouts/*.exe`, `metadata/streams/*.exe` | `generators/MetadataVariants` (dnlib) over TestApp and `generators/StreamProbe` |
| `sections` | `metadata/sections/*.exe` | `generators/SectionLayouts` over `generators/SectionProbe` (built with `mcs`, whose headers leave room for one more section) |
| `debug` | `debug/<form>/TestApp.exe` (+ `.pdb`) | TestApp built with portable, embedded, deterministic and no debug information |
| `pdb` | `pdb/<variant>/PdbProbe.dll` (+ `.pdb`, `PdbProbeLib.dll`) | `generators/PdbProbe`, whose Portable PDB has a row of every PDB table and a record of every custom debug information kind C# writes: Debug with a standalone PDB (`portable`), embedded (`embedded`), Release (`release`), and Debug without a path map or determinism (`unmapped`); and `pdb/vb/PdbProbeVb.dll` from `generators/PdbProbeVb`, for the records only Visual Basic writes |
| `winmd` | `winmd/Windows.Wdk.winmd` | the metadata-only assembly from the win32metadata project |
| `oracle` | `oracle.tsv` | every sample run on three runtimes (below) |

Every packer sample is protected from the `original.exe` in its own directory.

JIEJIE.NET draws fresh keys and names on every run: regenerating its samples changes every
byte (measured: two runs of the same build, 9 of 9 samples differ) while the oracle's
verdicts stay the same. Whether the other protectors are deterministic is not measured.

**Why each protector runs as its .NET Framework build.** Run on .NET (Core), BitMono,
Obfuscar and JIEJIE bind the code they inject to the runtime they run on
(`System.Private.CoreLib 8.0/10.0`, `System.Runtime 4.0.0.0`), so their output does not
load on the .NET Framework 4.8 TestApp targets. The samples made that way before this
factory existed did not load: 12 of 15 BitMono, 4 of 5 Obfuscar and 6 of 9 JIEJIE samples.

**JIEJIE.NET.** Its .NET Framework project file is DRM-encrypted, so the factory builds
its .NET Core project's sources for net48. Two things make that work:

- JIEJIE disassembles its input with ildasm.exe, which ships only with the Windows SDK.
  `generators/IldasmShim` stands in for it, running Microsoft's standalone ildasm (the
  `runtime.win-x64.Microsoft.NETCore.ILDAsm` package) without the two options that build
  does not accept (`/forward`, `/nobar`).
- Upstream defect: the IL templates JIEJIE injects name .NET (Core) reference
  assemblies (`System.Runtime`, `System.Collections`, `System.Threading`,
  `System.Threading.Thread`) outside their `#if DOTNETCORE` forms, and its .NET
  Framework build maps none of them. `generators/IlRetarget` points each reference at
  the assembly that defines the type on the .NET Framework, as reflection there reports
  it (157 references, all to mscorlib).

## The oracle

`oracle.tsv` has one row per sample: its path, sha256, and for each runtime (the .NET
Framework 4.8 under Wine, CoreCLR, Mono) whether it runs (exit code 0), whether its
output matches its unprotected build's on that runtime (`yes`, `no`, or `unordered`:
the same lines in another order), and for a stream experiment its output itself.

Packer samples whose output does not match on the .NET Framework, and why:

| Sample | Cause |
|---|---|
| BitMono `bitdecompiler`, `packer` | `[RuntimeMonikerMono]` protections: both CLRs refuse the image (`BadImageFormatException`); Mono runs them and matches |
| BitMono `bitdotnet`, `pe_combined`, `maximum` | `BitDotNet` writes the PE signature as `PE\x01\0` and zeroes the CLI header's `cb`, runtime version and metadata size; only Unity's Mono loader ignores those fields, and it is not redistributable |
| BitMono `junk` | `BitMethodDotnet` + `BillionNops`: both CLRs reject the body (`InvalidProgramException`); Mono runs it and matches |
| BitMono 0.39.0 `dotnethook`, `maximum_il` | its hook stubs are static methods with instance signatures, refused by every runtime ("The signature is incorrect"); fixed upstream in 17b12e2c (0.43.0) |
| BitMono 0.45.0 `dotnethook`, `maximum_il` | the stubs load, but the runtime patch (`Hooking.MakeHook`) leaves the program printing nothing on the .NET Framework and failing its module initializer on Mono; JIT inlining is ruled out (same result with `COMPlus_JITMinOpts=1`). Suspected, unconfirmed: the 13-byte x64 jump is written over a stub body shorter than that |
| BitMono `unmanagedstring` | runs on the .NET Framework only: it calls native x86/x64 code, which the Linux-hosted CoreCLR and Mono cannot execute |
| JIEJIE (all) | `unordered`: JIEJIE reorders the manifest resources, so `GetManifestResourceNames` lists them in another order |
| ConfuserEx `typescramble` | fails on every runtime: the scrambler re-scopes the `System.Collections.Generic.List'1` reference to TestApp itself (`TypeLoadException`; Mono asserts in its JIT). The maintainer calls the protection "very very unstable" and removed it upstream (mkaring/ConfuserEx#140, bd71639), though 1.6.0 still ships it |
| .NET Reactor (all) | made with an unregistered .NET Reactor: each throws "This assembly is protected by an unregistered version of Eziriz's .NET Reactor" by design |

## How the CLR reads the stream directory

Measured with `metadata/streams` (StreamProbe prints one value from each heap; a repeated
header points at a copy of its heap with that value changed) and `metadata/layouts`. The
.NET Framework 4.8 and CoreCLR agree on every experiment; Mono accepts more (of the images
both CLRs refuse below it rejects only a header it reads that points out of range, and a
junk tables stream it reads, taking the last of two `#~`).

The CLR refuses the image when:

- any header's offset or size reaches past the metadata, whatever its name and whether or
  not its stream is then read (`unknown_bad_*`, `us_shadowed_bad_offset`);
- a header's name with its terminating zero is longer than 32 bytes (`unknown_name_32`);
- there is more than one tables stream (`tables_*`, valid copies included);
- `#Schema` stands before the tables header (`schema_before*`).

Otherwise, of the headers repeating a heap's name it reads:

| Directory | Header read |
|---|---|
| `#~` tables, no `#Schema` | the **last** |
| `#-` tables | the **first** |
| `#Schema` after the tables header | the **first** (ConfuserEx's "invalid metadata" relies on this) |

- Names the CLR does not use are ignored; 45 headers load (`unknown_after_40`).
- `#JTD` beside `#-` tables (CoreCLR's "minimal delta" marker) makes every index column
  four bytes wide, heap indices included, whatever HeapSizes says:
  `metadata/layouts/minimal_delta_all{,_heapsizes}.exe` run, `minimal_delta_tables_only`
  (heap indices left at their HeapSizes width) and the normal-width `jtd_*_enc` fail. In
  `#~` metadata `#JTD` and `#Pdb` change nothing. Mono reads no minimal-delta tables.
- The `#~` header's ExtraData word (HeapSizes `0x40`) is skipped, `#-` metadata with
  HasDelete (`0x80`) loads, and HeapSizes bits `0x08`, `0x10` and `0x20` are ignored
  (`metadata/layouts`).

## How the runtimes read the bytes at an RVA

Measured with `metadata/sections`: SectionProbe prints the 32 bytes of an RVA field and calls
a method, and each experiment adds a section `.probe` of chosen VirtualSize, SizeOfRawData
and PointerToRawData, filled with a pattern that names each byte's offset, and moves the
field's data and the method's body into it.

| Experiment | .NET Framework | CoreCLR | Mono |
|---|---|---|---|
| data and body inside the raw data and VirtualSize (`inside`) | the file's bytes, runs | the same | the same |
| data past SizeOfRawData, within VirtualSize (`zero_fill`, `data_straddles_raw_end`) | zeros | zeros | zeros (crashes on `zero_fill`) |
| data past VirtualSize, within the raw data (`data_past_virtual_size*`, `data_straddles_virtual_size`) | the file's bytes | zeros | the file's bytes |
| a body past VirtualSize, in part or whole (`body_*`) | `BadImageFormatException` | `BadImageFormatException` | runs |
| data at an RVA in the headers (`header_rva`) | the bytes 16 before it | the header's bytes | crashes |
| VirtualSize 0, PointerToRawData not a multiple of FileAlignment, raw data past the file (`virtual_size_zero`, `pointer_unaligned`, `raw_past_file`) | refuses the image | refuses the image | runs the first, crashes on the others |

So a section is its VirtualSize bytes, the raw data then zeros, and nothing else is read the
same by both Microsoft runtimes. dotscope's `file::sectionmap` reads only that and
`tests/it/sections.rs` holds it to these rows. The .NET Framework column is measured under
Wine's loader, not Windows'.

## Other layout fixtures

`metadata/layouts/two_corelibs_foreign_{first,last}.exe` import `System.RuntimeTypeHandle`
from System.Private.CoreLib as well as from TestApp's own mscorlib, with the foreign TypeRef
listed before and after the program's: a module's core library types must resolve to its
own core library whichever the table lists first. In `foreign_first` TestApp's own code
uses the foreign TypeRef, so it runs only on CoreCLR; `foreign_last` runs everywhere.
