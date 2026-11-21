# Symbol Renaming (Stage 15)

Analysis of .NET Reactor 7.5.0 symbol renaming based on reverse engineering
`reactor_obfuscation.exe` (18,432 bytes, 46 methods) against `original.exe`
(14,336 bytes, 35 methods) using dotscope disassembly.

## File-Level Changes

| Property | Original | Protected | Delta |
|----------|----------|-----------|-------|
| File size | 14,336 | 18,432 | +4,096 (28.6%) |
| TypeDef rows | 13 | 28 | +15 |
| MethodDef rows | 35 | 46 | +11 |
| Constant table | 15 rows | 0 rows | removed |
| Sorted tables | 0x000016003301FA00 | 0x0000000000000000 | cleared |


## Naming Convention (Standard Mode)

All original type and method names are replaced with random alphanumeric strings:

- **Namespace names**: Random 18-char strings (e.g., `On02TF2P7MuGubquCs`)
- **Type names**: Random 18-char strings (e.g., `Rk4EYsPxb6dv47Ueub`)
- **Method names**: Random 9-char strings (e.g., `HhhIOMRed`, `SmkeDYgMW`)
- **Special methods preserved**: `.ctor`, `.cctor` names remain intact (ECMA-335 requirement)

### Example Mapping

| Original | Obfuscated Namespace.Type | Obfuscated Method |
|----------|--------------------------|-------------------|
| `ConfuserExTestApp.Program::Main` | `On02TF2P7MuGubquCs.Rk4EYsPxb6dv47Ueub` | `HhhIOMRed` |
| `ConfuserExTestApp.Greeter` | `dQ4JiRji7ha9M01XD3.t8JubRuTexuLxLeNiE` | `SmkeDYgMW`, `lCZOxnVpv`, `t9b8Nh5lg` |
| `ConfuserExTestApp.Calculator` | `s4ZMwdDZZIS0CxvoeV.UNQKLXoSlL8VdNhZ0k` | `AEUFDPbqw`, `mMpZW66bo`, `MPalEiwbe` |
| `ConfuserExTestApp.ControlFlowDemo` | `D2QLYmc3Hn5qOHuX9O.aywuUySFJF5pnSxNyw` | `CgvxAya9b`, `SXHNq5amX`, `HourhaVwp` |
| `ConfuserExTestApp.SecretHolder` | `jFf73IdLPIsBaKfBMP.P0WrqGgP5dh3HXnnjo` | `Bj7JELwbp`, `rlOMdqRv2`, `kTE0HZAI3` |
| `ConfuserExTestApp.ExtendedPatterns` | `bCbGema32Cvr0njpkp.wOmmC9LYmPLDnLVSB8` | `nUTU181kB`, `P73Y0Hdx6` |


## Metadata Changes

- **Constant table removed**: Original had 15 rows for enum defaults; obfuscated has 0.
  The Constant table is absent from the valid tables bitmask.
- **ClassLayout table**: 1 -> 12 (+11 injected struct layouts for
  `<PrivateImplementationDetails>` types)
- **Sorted tables bitmask cleared**: Set to all zeros (standard NR behavior)


## Deobfuscation Notes

Renaming is **irreversible**: the original names are permanently lost. dotscope's
renamer replaces them with short sequential names (`A`, `a`, `f_a`, `p_a`) so that the
output is readable, but it cannot recover the originals. The NRS `SymbolRenamer` stage (Stage 15) similarly uses de4dot's
renamer infrastructure to assign new readable names.
