// Writes copies of an input assembly with metadata layouts the CLR's reader accepts but
// ECMA-335 does not describe, or describes only loosely, one variant per file, through
// dnlib (whose writer options ConfuserEx's "invalid metadata" protection is built from).
//
//   MetadataVariants layouts <input.exe> <output-dir>
//   MetadataVariants streams <StreamProbe.exe> <output-dir>
//
// `layouts` covers the `#~` header: the ExtraData word (HeapSizes 0x40), the HasDelete bit
// (0x80) and uncompressed `#-` metadata. Its input is TestApp, so a variant that runs and
// prints what TestApp prints is one the CLR reads as intended.
//
// `streams` covers the stream directory: repeated headers, unknown names and the header
// count. Its input is StreamProbe, which prints one value from each heap. A repeated header
// points at a copy of its heap with that value changed, so the output says which header
// of the name the CLR read; a repeat that would break every lookup if read (`junk_*`) says
// whether the CLR reads it at all.

using System.Numerics;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.MD;
using dnlib.DotNet.Writer;

if (args.Length != 3 || (args[0] != "layouts" && args[0] != "streams"))
{
    Console.Error.WriteLine("usage: MetadataVariants layouts|streams <input.exe> <output-dir>");
    return 2;
}

var (mode, input, outputDir) = (args[0], args[1], args[2]);
Directory.CreateDirectory(outputDir);
var inputBytes = File.ReadAllBytes(input);

// Byte edits applied to a variant after dnlib writes it, for layouts dnlib cannot express:
// stream header fields out of range, HeapSizes bits it does not set.
var patches = new Dictionary<string, Action<byte[]>>();

var variants = mode == "layouts" ? Layouts() : Streams();
foreach (var (name, configure) in variants)
{
    using var module = ModuleDefMD.Load(inputBytes);
    var options = new ModuleWriterOptions(module);
    // Keep every row, token and heap offset where the input has them, so a variant differs
    // from the input only in the layout under test, and a heap copied from the input is
    // valid in the output.
    options.MetadataOptions.Flags |= MetadataFlags.PreserveAll;
    configure(module, options);
    var path = Path.Combine(outputDir, name + ".exe");
    if (patches.TryGetValue(name, out var patch))
    {
        // Patched in memory and written once: a patch that throws leaves no file behind
        // that would pass for the variant.
        using var stream = new MemoryStream();
        module.Write(stream, options);
        var bytes = stream.ToArray();
        patch(bytes);
        File.WriteAllBytes(path, bytes);
    }
    else
    {
        module.Write(path, options);
    }
    Console.WriteLine(path);
}

return 0;

IEnumerable<(string, Action<ModuleDef, ModuleWriterOptions>)> Layouts()
{
    yield return ("extradata", (_, o) => o.MetadataOptions.TablesHeapOptions.ExtraData = 0x12345678);
    // dnlib writes `#-` whenever HasDelete is set: the bit means nothing in `#~`.
    yield return ("hasdelete", (_, o) => o.MetadataOptions.TablesHeapOptions.HasDeletedRows = true);
    yield return ("enc", (_, o) => Enc(o));
    yield return ("enc_extradata", (_, o) =>
    {
        Enc(o);
        o.MetadataOptions.TablesHeapOptions.ExtraData = 0x12345678;
    });
    // `System.RuntimeTypeHandle` imported from System.Private.CoreLib as well as from the
    // program's own mscorlib, the foreign TypeRef listed before the program's and after
    // it: lookups of core library types must take the module's own core library whichever
    // scope the table lists first.
    yield return ("two_corelibs_foreign_first", (m, o) => TwoCoreLibraries(m, o, foreignFirst: true));
    yield return ("two_corelibs_foreign_last", (m, o) => TwoCoreLibraries(m, o, foreignFirst: false));
    // `#JTD` beside `#-` tables whose columns really are four bytes wide: every index column,
    // the same with HeapSizes declaring four-byte heap indices, and only the table and coded
    // index columns. Which of them run says how the CLR reads minimal-delta tables.
    yield return ("minimal_delta_all", (m, o) => MinimalDelta(m, o, widenHeaps: true, declareHeaps: false));
    yield return ("minimal_delta_all_heapsizes", (m, o) => MinimalDelta(m, o, widenHeaps: true, declareHeaps: true));
    yield return ("minimal_delta_tables_only", (m, o) => MinimalDelta(m, o, widenHeaps: false, declareHeaps: false));
    // HeapSizes bits ECMA-335 does not define, each set alone in an otherwise plain `#~`.
    foreach (var bit in new byte[] { 0x08, 0x10, 0x20 })
    {
        yield return Patched($"heapsizes_0x{bit:x2}", (_, _) => { }, SetHeapSizesBit(bit));
    }
}

// Writes `#-` tables beside a `#JTD` stream, with the table and coded index columns, and the
// heap index columns when `widenHeaps`, four bytes wide; `declareHeaps` also sets the
// HeapSizes bits for four-byte heap indices. The module is first written with uncompressed
// tables, and those tables re-encoded; method bodies precede the metadata, so the second
// write, whose tables stream is larger, leaves every RVA the tables hold where it was.
static void MinimalDelta(ModuleDef module, ModuleWriterOptions o, bool widenHeaps, bool declareHeaps)
{
    var first = new ModuleWriterOptions(module);
    first.MetadataOptions.Flags |= MetadataFlags.PreserveAll;
    Enc(first);
    using var written = new MemoryStream();
    module.Write(written, first);
    using var reread = ModuleDefMD.Load(written.ToArray());
    var tables = reread.Metadata.TablesStream;
    var original = Bytes(tables);

    var present = tables.MDTables.Where(t => !t.IsEmpty).ToList();
    var headerSize = 24 + 4 * BitOperations.PopCount(BitConverter.ToUInt64(original, 8));
    var widened = new List<byte>(original.AsSpan(0, headerSize).ToArray());
    if (declareHeaps)
    {
        widened[6] |= 0x07;
    }
    foreach (var table in present)
    {
        for (uint rid = 1; rid <= table.Rows; rid++)
        {
            foreach (var column in table.Columns)
            {
                if (!tables.TryReadColumn(table, rid, column, out var value))
                {
                    throw new InvalidOperationException($"{table.Table} row {rid} column {column.Name}");
                }
                var heap = column.ColumnSize is ColumnSize.Strings or ColumnSize.GUID or ColumnSize.Blob;
                var fixedSize = column.ColumnSize is ColumnSize.Byte or ColumnSize.Int16
                    or ColumnSize.UInt16 or ColumnSize.Int32 or ColumnSize.UInt32;
                var size = fixedSize || (heap && !widenHeaps) ? column.Size : 4;
                widened.AddRange(BitConverter.GetBytes(value).AsSpan(0, size).ToArray());
            }
        }
    }
    while (widened.Count % 4 != 0)
    {
        widened.Add(0);
    }

    Enc(o);
    var replacement = Raw("#-", widened.ToArray());
    o.MetadataOptions.MetadataHeapsAdded += (_, e) =>
    {
        e.Heaps[e.Heaps.FindIndex(h => h is TablesHeap)] = replacement;
        e.Heaps.Add(Raw("#JTD", 0, 0, 0, 0));
    };
}

// Imports System.RuntimeTypeHandle from System.Private.CoreLib as well as from mscorlib.
// TypeRef rows stay where the input has them, and a new one is appended:
// - foreign last: the new row is the foreign one, held by a static field of a type nothing
//   uses, so the program still runs where there is no System.Private.CoreLib;
// - foreign first: the program's own row is rescoped to System.Private.CoreLib, so the
//   foreign row is the earlier one and the program's code uses it, and the new row is the
//   mscorlib one. The program then runs only where System.Private.CoreLib exists.
static void TwoCoreLibraries(ModuleDef module, ModuleWriterOptions o, bool foreignFirst)
{
    var coreLib = new AssemblyRefUser(
        "System.Private.CoreLib", new Version(10, 0, 0, 0), new PublicKeyToken("7cec85d7bea7798e"));
    ITypeDefOrRef appended;
    if (foreignFirst)
    {
        var own = module.GetTypeRefs().Single(t => t.Namespace == "System" && t.Name == "RuntimeTypeHandle");
        appended = new TypeRefUser(module, "System", "RuntimeTypeHandle", own.ResolutionScope);
        own.ResolutionScope = coreLib;
    }
    else
    {
        appended = new TypeRefUser(module, "System", "RuntimeTypeHandle", coreLib);
    }
    var holder = new TypeDefUser("", "TwoCoreLibraries", module.CorLibTypes.Object.TypeDefOrRef)
    {
        Attributes = TypeAttributes.NotPublic | TypeAttributes.Abstract | TypeAttributes.Sealed,
    };
    holder.Fields.Add(new FieldDefUser(
        "handle", new FieldSig(new ValueTypeSig(appended)), FieldAttributes.Private | FieldAttributes.Static));
    module.Types.Add(holder);
}

IEnumerable<(string, Action<ModuleDef, ModuleWriterOptions>)> Streams()
{
    yield return ("probe", (_, _) => { });
    foreach (var enc in new[] { false, true })
    {
        var suffix = enc ? "_enc" : "";
        Action<ModuleWriterOptions> format = enc ? Enc : _ => { };
        foreach (var (heap, changed) in ChangedHeaps())
        {
            yield return ($"{heap}_after{suffix}", (_, o) => { format(o); After(o, changed); });
            yield return ($"{heap}_before{suffix}", (_, o) => { format(o); Before(o, changed); });
        }
        // Repeats of every heap that break every lookup if read: ConfuserEx's layout.
        yield return ($"junk_after{suffix}", (_, o) => { format(o); After(o, Junk()); });
        yield return ($"junk_before{suffix}", (_, o) => { format(o); Before(o, Junk()); });
    }
    // Names the CLR gives a meaning to although ECMA-335 does not list them: `#Schema`,
    // which ConfuserEx appends, `#Pdb` and `#JTD` (which makes every table column four
    // bytes wide). Each alone, and `#Schema` with a changed repeat of `#US` on either side,
    // to see whether it changes which header of a name is read.
    var us = ChangedHeaps().Single(h => h.Item1 == "us").Item2;
    foreach (var name in new[] { "Schema", "Pdb", "JTD" })
    {
        yield return ($"{name.ToLowerInvariant()}_after", (_, o) => After(o, Raw($"#{name}", 0, 0, 0, 0)));
        yield return ($"{name.ToLowerInvariant()}_before", (_, o) => Before(o, Raw($"#{name}", 0, 0, 0, 0)));
    }
    yield return ("us_after_schema_after", (_, o) => After(o, us, Raw("#Schema", 0, 0, 0, 0)));
    yield return ("schema_after_us_after", (_, o) => After(o, Raw("#Schema", 0, 0, 0, 0), us));
    yield return ("us_before_schema_after", (_, o) => { Before(o, us); After(o, Raw("#Schema", 0, 0, 0, 0)); });
    yield return ("junk_after_schema_after", (_, o) => After(o, [.. Junk(), Raw("#Schema", 0, 0, 0, 0)]));
    // Where `#Schema` may stand: right after the tables header, and before it but not first.
    yield return ("schema_after_tables", (_, o) => At(o, 1, Raw("#Schema", 0, 0, 0, 0)));
    yield return ("schema_before_tables", (_, o) => Before(o, Unknown(1)[0], Raw("#Schema", 0, 0, 0, 0)));
    yield return ("us_after_schema_after_tables", (_, o) =>
    {
        At(o, 1, Raw("#Schema", 0, 0, 0, 0));
        After(o, us);
    });
    // `#JTD` with uncompressed `#-` tables (CoreCLR's "minimal delta" marker).
    yield return ("jtd_after_enc", (_, o) => { Enc(o); After(o, Raw("#JTD", 0, 0, 0, 0)); });
    yield return ("jtd_before_enc", (_, o) => { Enc(o); Before(o, Raw("#JTD", 0, 0, 0, 0)); });
    // Headers whose offset or size points past the metadata: an unknown name, a repeat the
    // CLR does not read (before the real one in `#~`) and a repeat it does (after it).
    yield return Patched("unknown_bad_offset", (_, o) => After(o, Unknown(1)),
        SetHeaderField("#Unknown1", 0, size: false, 0x7FFF_FFF0));
    yield return Patched("unknown_bad_size", (_, o) => After(o, Unknown(1)),
        SetHeaderField("#Unknown1", 0, size: true, 0x7FFF_FFF0));
    yield return Patched("us_shadowed_bad_offset", (_, o) => Before(o, us),
        SetHeaderField("#US", 0, size: false, 0x7FFF_FFF0));
    yield return Patched("us_used_bad_offset", (_, o) => After(o, us),
        SetHeaderField("#US", 1, size: false, 0x7FFF_FFF0));
    // Name lengths around the CLR's 32-byte stream name buffer (dnlib writes at most 31
    // characters, so the longer ones are two headers merged into one), and a long directory.
    yield return ("unknown_name_31", (_, o) => After(o, Raw("#" + new string('n', 30), 0, 0, 0, 0)));
    foreach (var (length, first) in new[] { (32, 20), (40, 28) })
    {
        var a = "#" + new string('a', first - 1);
        yield return Patched($"unknown_name_{length}", (_, o) => After(o, Raw(a, 0, 0, 0, 0), Raw("#B", 0, 0, 0, 0)),
            MergeIntoLongName(a, "#" + new string('n', length - 1)));
    }
    yield return ("unknown_after_40", (_, o) => After(o, Unknown(40)));
    // Repeated tables streams: a junk `#~` (which no reader can use) after and before the real
    // one, and a junk `#-` after a real `#~`.
    yield return ("tables_junk_after", (_, o) => After(o, Raw("#~", new byte[24])));
    yield return ("tables_junk_before", (_, o) => Before(o, Raw("#~", new byte[24])));
    yield return ("tables_enc_junk_after", (_, o) => After(o, Raw("#-", new byte[24])));
    // A valid copy of the real `#~` with StringsMarker's TypeDef named `Main` instead: whether
    // it loads says whether a repeated tables stream is allowed at all, and the probe's
    // `strings=` line says which of the two the CLR read.
    var tables = ChangedTables();
    yield return ("tables_changed_after", (_, o) => After(o, tables));
    yield return ("tables_changed_before", (_, o) => Before(o, tables));
    // Names the CLR does not use.
    foreach (var count in new[] { 1, 2, 3, 4, 5, 6, 7, 8 })
    {
        yield return ($"unknown_after_{count}", (_, o) => After(o, Unknown(count)));
    }
    yield return ("unknown_before_1", (_, o) => Before(o, Unknown(1)));
    yield return ("unknown_name_hash", (_, o) => After(o, Raw("#", 0, 0, 0, 0)));
    yield return ("unknown_name_tilde_prefix", (_, o) => After(o, Raw("#~~", 0, 0, 0, 0)));
}

(string, Action<ModuleDef, ModuleWriterOptions>) Patched(
    string name, Action<ModuleDef, ModuleWriterOptions> configure, Action<byte[]> patch)
{
    patches[name] = patch;
    return (name, configure);
}

static void Enc(ModuleWriterOptions o) => o.MetadataOptions.TablesHeapOptions.UseENC = true;

// The stream headers of the metadata root in `image`: each name with the file positions of
// its offset and size fields, in directory order, and the root's file position.
static (int Root, List<(string Name, int OffsetField, int SizeField)> Headers) StreamHeaders(byte[] image)
{
    var root = image.AsSpan().IndexOf("BSJB"u8);
    var versionLength = BitConverter.ToInt32(image, root + 12);
    var at = root + 16 + versionLength + 2;
    var count = BitConverter.ToUInt16(image, at);
    at += 2;
    var headers = new List<(string, int, int)>();
    for (var i = 0; i < count; i++)
    {
        var end = Array.IndexOf(image, (byte)0, at + 8);
        var name = Encoding.ASCII.GetString(image, at + 8, end - at - 8);
        headers.Add((name, at, at + 4));
        at += 8 + ((name.Length + 4) & ~3);
    }
    return (root, headers);
}

// Sets the offset or size field of the `occurrence`th header named `name` (0 = first).
static Action<byte[]> SetHeaderField(string name, int occurrence, bool size, uint value) => image =>
{
    var header = StreamHeaders(image).Headers.Where(h => h.Name == name).ElementAt(occurrence);
    BitConverter.GetBytes(value).CopyTo(image, size ? header.SizeField : header.OffsetField);
};

// Merges the header named `first` with the one after it into a single header named `name`
// (keeping `first`'s offset and size) and drops the directory count by one. `name` must take
// the bytes the two headers' names and the second's fields took: the next header stays put.
static Action<byte[]> MergeIntoLongName(string first, string name) => image =>
{
    var (_, headers) = StreamHeaders(image);
    var index = headers.FindIndex(h => h.Name == first);
    var second = headers[index + 1];
    var start = headers[index].OffsetField + 8;
    var end = second.OffsetField + 8 + ((second.Name.Length + 4) & ~3);
    var padded = (name.Length + 4) & ~3;
    if (padded != end - start)
    {
        throw new InvalidOperationException($"'{name}' takes {padded} bytes, the merged headers {end - start}");
    }
    Array.Clear(image, start, end - start);
    Encoding.ASCII.GetBytes(name).CopyTo(image, start);
    var countField = headers[0].OffsetField - 2;
    BitConverter.GetBytes((ushort)(headers.Count - 1)).CopyTo(image, countField);
};

// Sets `bit` in the HeapSizes byte of the tables stream header.
static Action<byte[]> SetHeapSizesBit(byte bit) => image =>
{
    var (root, headers) = StreamHeaders(image);
    var tables = headers.Single(h => h.Name is "#~" or "#-");
    image[root + (int)BitConverter.ToUInt32(image, tables.OffsetField) + 6] |= bit;
};

// Heaps placed at `index` in the stream directory.
static void At(ModuleWriterOptions o, int index, params IHeap[] heaps) =>
    o.MetadataOptions.MetadataHeapsAdded += (_, e) => e.Heaps.InsertRange(index, heaps);

// Heaps placed before or after the real ones in the stream directory.
static void Before(ModuleWriterOptions o, params IHeap[] heaps) =>
    o.MetadataOptions.MetadataHeapsAdded += (_, e) => e.Heaps.InsertRange(0, heaps);

static void After(ModuleWriterOptions o, params IHeap[] heaps) =>
    o.MetadataOptions.MetadataHeapsAdded += (_, e) => e.Heaps.AddRange(heaps);

// A heap whose bytes are given verbatim.
static RawHeap Raw(string name, params byte[] data) => new(name, data);

static IHeap[] Junk() =>
[
    Raw("#Strings", 0, 0, 0, 0),
    Raw("#US", 0, 0, 0, 0),
    Raw("#Blob", 0, 0, 0, 0),
    Raw("#GUID", new byte[16]),
];

static IHeap[] Unknown(int count) =>
    Enumerable.Range(1, count).Select(i => (IHeap)Raw($"#Unknown{i}", 0, 0, 0, 0)).ToArray();

// Each StreamProbe heap with the value the probe prints from it changed: the case of the
// marker text swapped, and the MVID's bytes inverted. Offsets and lengths are unchanged.
IEnumerable<(string, IHeap)> ChangedHeaps()
{
    using var module = ModuleDefMD.Load(inputBytes);
    var md = module.Metadata;
    yield return ("strings", Raw("#Strings", SwapCase(Bytes(md.StringsStream), Encoding.ASCII.GetBytes("StringsMarker"))));
    yield return ("us", Raw("#US", SwapCase(Bytes(md.USStream), Encoding.Unicode.GetBytes("UserStringMarker"))));
    yield return ("blob", Raw("#Blob", SwapCase(Bytes(md.BlobStream), Encoding.ASCII.GetBytes("BlobMarker"))));
    yield return ("guid", Raw("#GUID", Bytes(md.GuidStream).Select(b => (byte)~b).ToArray()));
}

// The input's `#~` stream with the Name column of StringsMarker's TypeDef row pointing at
// the string `Main` (its Main method's name), so the probe prints `strings=Main` when the
// CLR reads this copy.
IHeap ChangedTables()
{
    using var module = ModuleDefMD.Load(inputBytes);
    var md = module.Metadata;
    var stream = md.TablesStream;
    var bytes = Bytes(stream);
    var type = module.Types.Single(t => t.Name == "StringsMarker");
    var main = type.Methods.Single(m => m.Name == "Main");
    if (!stream.TryReadMethodRow(main.Rid, out var mainRow))
    {
        throw new InvalidOperationException("no Method row for Main");
    }
    var table = stream.TypeDefTable;
    var name = table.Columns[1];
    var at = (int)((uint)table.StartOffset - (uint)stream.StartOffset)
        + (int)((type.Rid - 1) * table.RowSize) + name.Offset;
    var index = BitConverter.GetBytes(mainRow.Name);
    Array.Copy(index, 0, bytes, at, name.Size);
    return Raw("#~", bytes);
}

static byte[] Bytes(dnlib.DotNet.MD.DotNetStream stream)
{
    var reader = stream.CreateReader();
    return reader.ReadBytes((int)reader.Length);
}

// Swaps the case of the ASCII letters of the one occurrence of `marker` in `heap`.
static byte[] SwapCase(byte[] heap, byte[] marker)
{
    var at = heap.AsSpan().IndexOf(marker);
    if (at < 0 || heap.AsSpan(at + 1).IndexOf(marker) >= 0)
    {
        throw new InvalidOperationException("the marker must occur exactly once in its heap");
    }
    for (var i = at; i < at + marker.Length; i++)
    {
        if (char.IsAsciiLetter((char)heap[i]))
        {
            heap[i] ^= 0x20;
        }
    }
    return heap;
}

sealed class RawHeap(string name, byte[] data) : HeapBase
{
    public override string Name => name;

    public override uint GetRawLength() => (uint)data.Length;

    protected override void WriteToImpl(DataWriter writer) => writer.WriteBytes(data);
}
