// The canonical dump of an assembly as System.Reflection.Metadata reads it.
//
// dotscope's `testkit::dump::CanonicalDump` describes an assembly path by path: its sections,
// data directories, debug entries, CLI header, every table row with its heap columns resolved,
// every method body decoded, every field's initial data and every embedded resource. This
// program writes the same description from what Microsoft's reader, System.Reflection.Metadata
// (SRM), reads in the same file, as a JSON object of path to value, so that a difference
// between the two is a difference in how the file was read. The paths and values follow the
// format `testkit::dump` documents.
//
// A Portable PDB is dumped under `Pdb.`: the one the image embeds, read with SRM's
// `ReadEmbeddedPortablePdbDebugDirectoryData`, and a standalone `.pdb` file given as a path,
// read with `MetadataReaderProvider.FromPortablePdbStream`. Its document names, sequence
// points and imports are the values SRM decodes.
//
// SRM reads the PE headers, the metadata root, the heaps, the method bodies and every table
// column its object model exposes; the columns it does not expose (the lists of TypeDef and
// MethodDef, the tables without a row accessor such as ClassLayout or ImplMap) are read from
// the row SRM locates, with the column widths ECMA-335 II.24.2.6 gives. Those widths are
// checked against the row size SRM computes for every table. Instructions are decoded with the
// opcode table of System.Reflection.Emit.
//
// Usage: SrmDump <samples dir> <output dir> [<path under samples dir>...]
// Each path's dump is written to `<output dir>/<path>.json`. Without paths, every fixture
// `MANIFEST.toml` in the samples directory lists with the suite "srm" is dumped.

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

static class SrmDump
{
    static int Main(string[] args)
    {
        if (args.Length < 2)
        {
            Console.Error.WriteLine("usage: SrmDump <samples dir> <output dir> [<path>...]");
            return 2;
        }
        var samples = args[0];
        var output = args[1];
        var paths = args.Length > 2 ? args.Skip(2).ToList() : SuiteFixtures(samples, "srm");
        foreach (var path in paths)
        {
            var target = Path.Combine(output, path + ".json");
            Directory.CreateDirectory(Path.GetDirectoryName(target));
            File.WriteAllText(target, Json(DumpFile(Path.Combine(samples, path))), new UTF8Encoding(false));
        }
        return 0;
    }

    // The fixtures the manifest tags with `suite`: each `[[fixture]]` entry's `path` and
    // `suites` lines.
    static List<string> SuiteFixtures(string samples, string suite)
    {
        var fixtures = new List<string>();
        string path = null;
        foreach (var line in File.ReadAllLines(Path.Combine(samples, "MANIFEST.toml")))
        {
            var text = line.Trim();
            if (text == "[[fixture]]")
                path = null;
            else if (text.StartsWith("path = "))
                path = text.Substring(7).Trim('"');
            else if (text.StartsWith("suites = ") && path != null && text.Contains("\"" + suite + "\""))
                fixtures.Add(path);
        }
        fixtures.Sort(StringComparer.Ordinal);
        return fixtures;
    }

    static SortedDictionary<string, string> DumpFile(string file)
    {
        var dump = new SortedDictionary<string, string>(new Utf8Order());
        try
        {
            var bytes = File.ReadAllBytes(file);
            if (file.EndsWith(".pdb", StringComparison.Ordinal))
            {
                using (var provider = MetadataReaderProvider.FromPortablePdbStream(new MemoryStream(bytes)))
                {
                    var reader = provider.GetMetadataReader(MetadataReaderOptions.None, new Decoder());
                    new Dumper(null, reader, dump, bytes, "Pdb.").RunPdb();
                }
            }
            else
            {
                using (var pe = new PEReader(new MemoryStream(bytes)))
                {
                    var reader = pe.GetMetadataReader(MetadataReaderOptions.None, new Decoder());
                    new Dumper(pe, reader, dump, pe.GetMetadata().GetContent().ToArray(), "").Run();
                }
            }
        }
        catch (Exception error)
        {
            dump.Clear();
            dump["Image"] = "unreadable: " + error.GetType().Name + ": " + error.Message;
        }
        return dump;
    }

    // The dump as a JSON object, a line per entry. Keys sort by their UTF-8 bytes, as
    // dotscope's do.
    static string Json(SortedDictionary<string, string> dump)
    {
        var text = new StringBuilder("{\n");
        var first = true;
        foreach (var entry in dump)
        {
            if (!first)
                text.Append(",\n");
            first = false;
            text.Append("  ").Append(JsonString(entry.Key)).Append(": ").Append(JsonString(entry.Value));
        }
        return text.Append("\n}\n").ToString();
    }

    static string JsonString(string value)
    {
        var text = new StringBuilder("\"");
        foreach (var c in value)
        {
            if (c == '"' || c == '\\')
                text.Append('\\').Append(c);
            else if (c < 0x20)
                text.Append("\\u").Append(((int)c).ToString("x4"));
            else
                text.Append(c);
        }
        return text.Append('"').ToString();
    }

    sealed class Utf8Order : IComparer<string>
    {
        public int Compare(string x, string y)
        {
            var a = Encoding.UTF8.GetBytes(x);
            var b = Encoding.UTF8.GetBytes(y);
            for (var i = 0; i < Math.Min(a.Length, b.Length); i++)
                if (a[i] != b[i])
                    return a[i].CompareTo(b[i]);
            return a.Length.CompareTo(b.Length);
        }
    }

    // A #Strings entry as the dump writes it, from the bytes SRM hands over: quoted when it is
    // UTF-8, its bytes in hex when it is not.
    internal sealed unsafe class Decoder : MetadataStringDecoder
    {
        static readonly UTF8Encoding Strict = new UTF8Encoding(false, true);

        public Decoder() : base(Encoding.UTF8) { }

        public override string GetString(byte* bytes, int byteCount)
        {
            var data = new byte[byteCount];
            for (var i = 0; i < byteCount; i++)
                data[i] = bytes[i];
            try
            {
                return Quoted(Strict.GetString(data));
            }
            catch (DecoderFallbackException)
            {
                return "bytes[" + Hex(data) + "]";
            }
        }
    }

    // Text as the dump quotes it: `\`, `"` and the control characters escaped, any other
    // character as it is, and a UTF-16 surrogate without its pair as its code unit.
    internal static string Quoted(string value)
    {
        var text = new StringBuilder("\"");
        for (var i = 0; i < value.Length; i++)
        {
            var c = value[i];
            if (char.IsHighSurrogate(c) && i + 1 < value.Length && char.IsLowSurrogate(value[i + 1]))
            {
                text.Append(c).Append(value[++i]);
            }
            else if (c == '\\' || c == '"')
            {
                text.Append('\\').Append(c);
            }
            else if (c < 0x20 || c == 0x7f || char.IsSurrogate(c))
            {
                text.Append("\\u{").Append(((int)c).ToString("x")).Append('}');
            }
            else
            {
                text.Append(c);
            }
        }
        return text.Append('"').ToString();
    }

    internal static string Hex(IEnumerable<byte> bytes)
    {
        var text = new StringBuilder();
        foreach (var b in bytes)
            text.Append(b.ToString("x2"));
        return text.ToString();
    }

    internal static string Sha256(byte[] data)
    {
        using (var sha = SHA256.Create())
            return Hex(sha.ComputeHash(data));
    }
}

// A table column, in ECMA-335 II.22 order.
sealed class Column
{
    public char Kind; // '1', '2', '4': a constant of that many bytes; 'S', 'B', 'G': a heap
                      // index; 'I': a simple index; 'C': a coded index
    public int Target; // the table of a simple index, the family of a coded index

    public bool IsHeap { get { return Kind == 'S' || Kind == 'B' || Kind == 'G'; } }
}

sealed class Dumper
{
    readonly PEReader pe;
    readonly MetadataReader reader;
    readonly IDictionary<string, string> dump;
    readonly byte[] metadata;
    // The prefix of every path: `Pdb.` for a Portable PDB's
    readonly string prefix;
    ulong valid;
    int heapSizes;
    // A Portable PDB's `#Pdb` stream row counts, which size its indexes into the image's
    // tables; null for an image
    int[] external;

    // The tables, by number: their names as dotscope's TableId spells them, and their columns
    static readonly Dictionary<int, string> Names = new Dictionary<int, string>();
    static readonly Dictionary<int, Column[]> Schema = new Dictionary<int, Column[]>();
    static readonly Dictionary<int, string> Specs = new Dictionary<int, string>();

    // The coded-index families of II.24.2.6, each table a tag names (-1: unassigned)
    static readonly int[][] Coded =
    {
        new[] { 0x02, 0x01, 0x1B }, // 0 TypeDefOrRef
        new[] { 0x04, 0x08, 0x17 }, // 1 HasConstant
        new[] { 0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x00, 0x0E, 0x17, 0x14, 0x11, 0x1A,
                0x1B, 0x20, 0x23, 0x26, 0x27, 0x28, 0x2A, 0x2C, 0x2B }, // 2 HasCustomAttribute
        new[] { 0x04, 0x08 }, // 3 HasFieldMarshal
        new[] { 0x02, 0x06, 0x20 }, // 4 HasDeclSecurity
        new[] { 0x02, 0x01, 0x1A, 0x06, 0x1B }, // 5 MemberRefParent
        new[] { 0x14, 0x17 }, // 6 HasSemantics
        new[] { 0x06, 0x0A }, // 7 MethodDefOrRef
        new[] { 0x04, 0x06 }, // 8 MemberForwarded
        new[] { 0x26, 0x23, 0x27 }, // 9 Implementation
        new[] { -1, -1, 0x06, 0x0A, -1 }, // 10 CustomAttributeType
        new[] { 0x00, 0x1A, 0x23, 0x01 }, // 11 ResolutionScope
        new[] { 0x02, 0x06 }, // 12 TypeOrMethodDef
        new[] { 0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x00, 0x0E, 0x17, 0x14, 0x11, 0x1A,
                0x1B, 0x20, 0x23, 0x26, 0x27, 0x28, 0x2A, 0x2C, 0x2B, 0x30, 0x32, 0x33, 0x34,
                0x35 }, // 13 HasCustomDebugInformation
    };

    static readonly string[] CodedNames =
    {
        "TypeDefOrRef", "HasConstant", "HasCustomAttribute", "HasFieldMarshal",
        "HasDeclSecurity", "MemberRefParent", "HasSemantics", "MethodDefOrRef",
        "MemberForwarded", "Implementation", "CustomAttributeType", "ResolutionScope",
        "TypeOrMethodDef", "HasCustomDebugInformation",
    };

    static Dumper()
    {
        Table(0x00, "Module", "2 S G G G");
        Table(0x01, "TypeRef", "ResolutionScope S S");
        Table(0x02, "TypeDef", "4 S S TypeDefOrRef Field MethodDef");
        Table(0x03, "FieldPtr", "Field");
        Table(0x04, "Field", "2 S B");
        Table(0x05, "MethodPtr", "MethodDef");
        Table(0x06, "MethodDef", "4 2 2 S B Param");
        Table(0x07, "ParamPtr", "Param");
        Table(0x08, "Param", "2 2 S");
        Table(0x09, "InterfaceImpl", "TypeDef TypeDefOrRef");
        Table(0x0A, "MemberRef", "MemberRefParent S B");
        Table(0x0B, "Constant", "1 1 HasConstant B");
        Table(0x0C, "CustomAttribute", "HasCustomAttribute CustomAttributeType B");
        Table(0x0D, "FieldMarshal", "HasFieldMarshal B");
        Table(0x0E, "DeclSecurity", "2 HasDeclSecurity B");
        Table(0x0F, "ClassLayout", "2 4 TypeDef");
        Table(0x10, "FieldLayout", "4 Field");
        Table(0x11, "StandAloneSig", "B");
        Table(0x12, "EventMap", "TypeDef Event");
        Table(0x13, "EventPtr", "Event");
        Table(0x14, "Event", "2 S TypeDefOrRef");
        Table(0x15, "PropertyMap", "TypeDef Property");
        Table(0x16, "PropertyPtr", "Property");
        Table(0x17, "Property", "2 S B");
        Table(0x18, "MethodSemantics", "2 MethodDef HasSemantics");
        Table(0x19, "MethodImpl", "TypeDef MethodDefOrRef MethodDefOrRef");
        Table(0x1A, "ModuleRef", "S");
        Table(0x1B, "TypeSpec", "B");
        Table(0x1C, "ImplMap", "2 MemberForwarded S ModuleRef");
        Table(0x1D, "FieldRVA", "4 Field");
        Table(0x1E, "EncLog", "4 4");
        Table(0x1F, "EncMap", "4");
        Table(0x20, "Assembly", "4 2 2 2 2 4 B S S");
        Table(0x21, "AssemblyProcessor", "4");
        Table(0x22, "AssemblyOS", "4 4 4");
        Table(0x23, "AssemblyRef", "2 2 2 2 4 B S S B");
        Table(0x24, "AssemblyRefProcessor", "4 AssemblyRef");
        Table(0x25, "AssemblyRefOS", "4 4 4 AssemblyRef");
        Table(0x26, "File", "4 S B");
        Table(0x27, "ExportedType", "4 4 S S Implementation");
        Table(0x28, "ManifestResource", "4 4 S Implementation");
        Table(0x29, "NestedClass", "TypeDef TypeDef");
        Table(0x2A, "GenericParam", "2 2 TypeOrMethodDef S");
        Table(0x2B, "MethodSpec", "MethodDefOrRef B");
        Table(0x2C, "GenericParamConstraint", "GenericParam TypeDefOrRef");
        Table(0x30, "Document", "B G B G");
        Table(0x31, "MethodDebugInformation", "Document B");
        Table(0x32, "LocalScope", "MethodDef ImportScope LocalVariable LocalConstant 4 4");
        Table(0x33, "LocalVariable", "2 2 S");
        Table(0x34, "LocalConstant", "S B");
        Table(0x35, "ImportScope", "ImportScope B");
        Table(0x36, "StateMachineMethod", "MethodDef MethodDef");
        Table(0x37, "CustomDebugInformation", "HasCustomDebugInformation G B");
        // A column names a table by its name, which may come after it
        foreach (var number in Specs.Keys)
            Schema[number] = Specs[number].Split(' ').Select(column =>
            {
                if (column.Length == 1)
                    return new Column { Kind = column[0] };
                var family = Array.IndexOf(CodedNames, column);
                if (family >= 0)
                    return new Column { Kind = 'C', Target = family };
                return new Column { Kind = 'I', Target = Names.First(entry => entry.Value == column).Key };
            }).ToArray();
    }

    // A table's columns: a byte count, a heap (S, B, G), a coded-index family or a table name.
    static void Table(int number, string name, string columns)
    {
        Names[number] = name;
        Specs[number] = columns;
    }

    public Dumper(PEReader pe, MetadataReader reader, IDictionary<string, string> dump, byte[] metadata, string prefix)
    {
        this.pe = pe;
        this.reader = reader;
        this.dump = dump;
        this.metadata = metadata;
        this.prefix = prefix;
    }

    public void Run()
    {
        Structure();
        TablesHeader();
        Tables();
        DebugValues();
        EmbeddedPdb();
    }

    // A Portable PDB: its identity and entry point as SRM reads them, the row counts its
    // `#Pdb` stream records, and its tables.
    public void RunPdb()
    {
        var header = reader.DebugMetadataHeader;
        dump[prefix + "id"] = SrmDump.Hex(header.Id);
        dump[prefix + "entryPoint"] = "0x" + (header.EntryPoint.IsNil ? 0 : MetadataTokens.GetToken(header.EntryPoint)).ToString("x8");
        PdbStream();
        TablesHeader();
        Tables();
        DebugValues();
    }

    // The PDB the image embeds, the first EmbeddedPortablePdb entry of its debug directory.
    void EmbeddedPdb()
    {
        DebugDirectoryEntry embedded;
        try
        {
            embedded = pe.ReadDebugDirectory().FirstOrDefault(entry => entry.Type == DebugDirectoryEntryType.EmbeddedPortablePdb);
        }
        catch (BadImageFormatException)
        {
            dump["Pdb"] = "unreadable";
            return;
        }
        if (embedded.Type != DebugDirectoryEntryType.EmbeddedPortablePdb)
            return;
        try
        {
            using (var provider = pe.ReadEmbeddedPortablePdbDebugDirectoryData(embedded))
            {
                var pdb = provider.GetMetadataReader(MetadataReaderOptions.None, new SrmDump.Decoder());
                var bytes = new byte[pdb.MetadataLength];
                unsafe
                {
                    Marshal.Copy((IntPtr)pdb.MetadataPointer, bytes, 0, bytes.Length);
                }
                new Dumper(null, pdb, dump, bytes, "Pdb.").RunPdb();
            }
        }
        catch (Exception error) when (error is BadImageFormatException || error is InvalidDataException)
        {
            foreach (var key in dump.Keys.Where(key => key.StartsWith("Pdb.", StringComparison.Ordinal)).ToList())
                dump.Remove(key);
            dump["Pdb"] = "unreadable";
        }
    }

    // The `#Pdb` stream's row counts (SRM sizes the tables by them but does not expose them):
    // after the 20-byte id and the entry point, a mask of the tables the PDB references and a
    // count per bit, in table order.
    void PdbStream()
    {
        var at = Stream("#Pdb") + 24;
        var referenced = BitConverter.ToUInt64(metadata, at);
        at += 8;
        external = new int[64];
        for (var table = 0; table < 64; table++)
        {
            if ((referenced & (1UL << table)) == 0)
                continue;
            external[table] = BitConverter.ToInt32(metadata, at);
            at += 4;
            dump[prefix + "typeSystemRows[" + (Names.ContainsKey(table) ? Names[table] : table.ToString()) + "]"] = external[table].ToString();
        }
    }

    // The offset of the stream the metadata root names `name`, -1 without one.
    int Stream(string name)
    {
        var at = 12;
        var versionLength = BitConverter.ToInt32(metadata, at);
        at += 4 + versionLength + 2;
        int streams = BitConverter.ToUInt16(metadata, at);
        at += 2;
        var found = -1;
        for (var stream = 0; stream < streams; stream++)
        {
            var offset = BitConverter.ToInt32(metadata, at);
            var end = Array.IndexOf(metadata, (byte)0, at + 8);
            if (Encoding.ASCII.GetString(metadata, at + 8, end - at - 8) == name)
                found = offset;
            at = (end + 4) & ~3;
        }
        return found;
    }

    // Every row of every table the tables stream declares, and what an image's method bodies,
    // field RVAs and resources point at.
    void Tables()
    {
        var bodies = new List<KeyValuePair<int, uint[]>>();
        var resources = new List<uint[]>();
        var fieldRvas = new List<KeyValuePair<int, uint[]>>();
        foreach (var number in Schema.Keys.OrderBy(n => n))
        {
            if ((valid & (1UL << number)) == 0)
                continue;
            var rows = reader.GetTableRowCount((TableIndex)number);
            dump[prefix + Names[number] + ".rows"] = rows.ToString();
            var expected = Schema[number].Sum(column => Width(column));
            var actual = reader.GetTableRowSize((TableIndex)number);
            if (expected != actual)
                dump[prefix + Names[number] + ".layout"] = "SRM reads rows of " + actual + " bytes, ECMA-335 gives " + expected;
            for (var rid = 1; rid <= rows; rid++)
            {
                uint[] values;
                try
                {
                    values = Row(number, rid);
                }
                catch (BadImageFormatException)
                {
                    dump[prefix + Names[number] + "[" + rid + "]"] = "unreadable";
                    continue;
                }
                dump[prefix + Names[number] + "[" + rid + "]"] = Render(number, values);
                if (number == 0x06)
                    bodies.Add(new KeyValuePair<int, uint[]>(rid, values));
                else if (number == 0x1D)
                    fieldRvas.Add(new KeyValuePair<int, uint[]>(rid, values));
                else if (number == 0x28)
                    resources.Add(values);
            }
        }
        foreach (var method in bodies)
            // Native and runtime-provided code has no CIL body to read
            if (method.Value[0] != 0 && (method.Value[1] & 0x0003) == 0)
                dump["MethodDef[" + method.Key + "].body"] = Body((int)method.Value[0]);
        foreach (var row in fieldRvas)
            dump["FieldRVA[" + row.Key + "].data"] = FieldData(row.Value[0], row.Value[1]);
        foreach (var row in resources)
            Resource(row);
    }

    // The PE and CLI facts: sections, data directories, debug entries, the CLI header and the
    // metadata root's version.
    void Structure()
    {
        var headers = pe.PEHeaders;
        foreach (var section in headers.SectionHeaders)
            if (!section.Name.StartsWith(".reloc"))
                dump["Section[" + section.Name + "]"] = "characteristics 0x" + ((uint)section.SectionCharacteristics).ToString("x8");
        var pe32 = headers.PEHeader;
        // The certificate table and the base relocations are left out: a writer cannot keep a
        // signature over bytes it moved, and lays out the relocations its own code needs
        var directories = new[]
        {
            new KeyValuePair<string, DirectoryEntry>("ExportTable", pe32.ExportTableDirectory),
            new KeyValuePair<string, DirectoryEntry>("ImportTable", pe32.ImportTableDirectory),
            new KeyValuePair<string, DirectoryEntry>("ResourceTable", pe32.ResourceTableDirectory),
            new KeyValuePair<string, DirectoryEntry>("ExceptionTable", pe32.ExceptionTableDirectory),
            new KeyValuePair<string, DirectoryEntry>("Debug", pe32.DebugTableDirectory),
            new KeyValuePair<string, DirectoryEntry>("Architecture", pe32.CopyrightTableDirectory),
            new KeyValuePair<string, DirectoryEntry>("GlobalPtr", pe32.GlobalPointerTableDirectory),
            new KeyValuePair<string, DirectoryEntry>("TlsTable", pe32.ThreadLocalStorageTableDirectory),
            new KeyValuePair<string, DirectoryEntry>("LoadConfigTable", pe32.LoadConfigTableDirectory),
            new KeyValuePair<string, DirectoryEntry>("BoundImport", pe32.BoundImportTableDirectory),
            new KeyValuePair<string, DirectoryEntry>("ImportAddressTable", pe32.ImportAddressTableDirectory),
            new KeyValuePair<string, DirectoryEntry>("DelayImportDescriptor", pe32.DelayImportTableDirectory),
            new KeyValuePair<string, DirectoryEntry>("ClrRuntimeHeader", pe32.CorHeaderTableDirectory),
        };
        foreach (var directory in directories)
            if (directory.Value.RelativeVirtualAddress != 0 || directory.Value.Size != 0)
                dump["Directory[" + directory.Key + "]"] = "present";
        if (pe32.DebugTableDirectory.RelativeVirtualAddress != 0 && pe32.DebugTableDirectory.Size != 0)
        {
            try
            {
                var index = 0;
                var image = pe.GetEntireImage().GetContent();
                foreach (var entry in pe.ReadDebugDirectory())
                {
                    string data;
                    try
                    {
                        data = SrmDump.Sha256(image.Skip(entry.DataPointer).Take(entry.DataSize).ToArray());
                        if (entry.DataPointer + (long)entry.DataSize > image.Length)
                            data = null;
                    }
                    catch (ArgumentException)
                    {
                        data = null;
                    }
                    // SRM refuses an entry whose characteristics are not zero
                    dump["Debug[" + index++ + "]"] = "type " + (int)entry.Type + ", characteristics 0x0, version "
                        + entry.MajorVersion + "." + entry.MinorVersion + ", " + entry.DataSize + " bytes, sha256 "
                        + (data ?? "unreadable");
                }
            }
            catch (BadImageFormatException)
            {
                dump["Debug"] = "unreadable";
            }
        }
        var cli = headers.CorHeader;
        dump["Cli"] = "runtime " + cli.MajorRuntimeVersion + "." + cli.MinorRuntimeVersion + ", flags 0x"
            + ((int)cli.Flags).ToString("x") + ", entry point 0x" + cli.EntryPointTokenOrRelativeVirtualAddress.ToString("x8");
        dump["Metadata.version"] = reader.MetadataVersion;
    }

    // The tables stream's header (II.24.2.6), for what SRM does not expose: which tables it
    // declares present, and how wide its heap indexes are. SRM reads the last `#~` or `#-`
    // stream the root lists.
    void TablesHeader()
    {
        var at = 12;
        var versionLength = BitConverter.ToInt32(metadata, at);
        at += 4 + versionLength + 2;
        int streams = BitConverter.ToUInt16(metadata, at);
        at += 2;
        var tables = -1;
        for (var stream = 0; stream < streams; stream++)
        {
            var offset = BitConverter.ToInt32(metadata, at);
            var end = Array.IndexOf(metadata, (byte)0, at + 8);
            var name = Encoding.ASCII.GetString(metadata, at + 8, end - at - 8);
            if (name == "#~" || name == "#-")
                tables = offset;
            at = (end + 4) & ~3;
        }
        if (tables < 0)
            return;
        heapSizes = metadata[tables + 6];
        valid = BitConverter.ToUInt64(metadata, tables + 8);
    }

    int Rows(int table)
    {
        if (external != null && table < 0x30)
            return external[table];
        return Names.ContainsKey(table) && table < 0x40 ? reader.GetTableRowCount((TableIndex)table) : 0;
    }

    int Width(Column column)
    {
        switch (column.Kind)
        {
            case '1': return 1;
            case '2': return 2;
            case '4': return 4;
            case 'S': return (heapSizes & 0x01) != 0 ? 4 : 2;
            case 'G': return (heapSizes & 0x02) != 0 ? 4 : 2;
            case 'B': return (heapSizes & 0x04) != 0 ? 4 : 2;
            case 'I': return Rows(column.Target) < 0x10000 ? 2 : 4;
            default:
                var family = Coded[column.Target];
                var bits = TagBits(family.Length);
                var largest = family.Max(table => table < 0 ? 0 : Rows(table));
                return largest < (1 << (16 - bits)) ? 2 : 4;
        }
    }

    static int TagBits(int tables)
    {
        var bits = 0;
        while ((1 << bits) < tables)
            bits++;
        return bits;
    }

    // A row's column values: raw coded indexes, heap offsets, constants. SRM's accessors give
    // the columns it models; the rest come from the row's bytes where SRM places them.
    uint[] Row(int table, int rid)
    {
        var columns = Schema[table];
        var values = new uint[columns.Length];
        var at = reader.GetTableMetadataOffset((TableIndex)table) + (rid - 1) * reader.GetTableRowSize((TableIndex)table);
        for (var i = 0; i < columns.Length; i++)
        {
            var width = Width(columns[i]);
            values[i] = width == 1 ? metadata[at] : width == 2 ? BitConverter.ToUInt16(metadata, at) : BitConverter.ToUInt32(metadata, at);
            at += width;
        }
        switch (table)
        {
            case 0x00:
                if (rid == 1)
                {
                    var module = reader.GetModuleDefinition();
                    Set(values, (uint)module.Generation, Heap(module.Name), Heap(module.Mvid), Heap(module.GenerationId), Heap(module.BaseGenerationId));
                }
                break;
            case 0x01:
                {
                    var row = reader.GetTypeReference(MetadataTokens.TypeReferenceHandle(rid));
                    Set(values, Encode(11, row.ResolutionScope), Heap(row.Name), Heap(row.Namespace));
                }
                break;
            case 0x02:
                {
                    var row = reader.GetTypeDefinition(MetadataTokens.TypeDefinitionHandle(rid));
                    Set(values, (uint)row.Attributes, Heap(row.Name), Heap(row.Namespace), Encode(0, row.BaseType));
                }
                break;
            case 0x04:
                {
                    var row = reader.GetFieldDefinition(MetadataTokens.FieldDefinitionHandle(rid));
                    Set(values, (uint)row.Attributes, Heap(row.Name), Heap(row.Signature));
                }
                break;
            case 0x06:
                {
                    var row = reader.GetMethodDefinition(MetadataTokens.MethodDefinitionHandle(rid));
                    Set(values, (uint)row.RelativeVirtualAddress, (uint)row.ImplAttributes, (uint)row.Attributes, Heap(row.Name), Heap(row.Signature));
                }
                break;
            case 0x08:
                {
                    var row = reader.GetParameter(MetadataTokens.ParameterHandle(rid));
                    Set(values, (uint)row.Attributes, (uint)row.SequenceNumber, Heap(row.Name));
                }
                break;
            case 0x09:
                {
                    var row = reader.GetInterfaceImplementation(MetadataTokens.InterfaceImplementationHandle(rid));
                    values[1] = Encode(0, row.Interface);
                }
                break;
            case 0x0A:
                {
                    var row = reader.GetMemberReference(MetadataTokens.MemberReferenceHandle(rid));
                    Set(values, Encode(5, row.Parent), Heap(row.Name), Heap(row.Signature));
                }
                break;
            case 0x0B:
                {
                    var row = reader.GetConstant(MetadataTokens.ConstantHandle(rid));
                    values[0] = (uint)row.TypeCode;
                    values[2] = Encode(1, row.Parent);
                    values[3] = Heap(row.Value);
                }
                break;
            case 0x0C:
                {
                    var row = reader.GetCustomAttribute(MetadataTokens.CustomAttributeHandle(rid));
                    Set(values, Encode(2, row.Parent), Encode(10, row.Constructor), Heap(row.Value));
                }
                break;
            case 0x0E:
                {
                    var row = reader.GetDeclarativeSecurityAttribute(MetadataTokens.DeclarativeSecurityAttributeHandle(rid));
                    Set(values, (uint)row.Action, Encode(4, row.Parent), Heap(row.PermissionSet));
                }
                break;
            case 0x11:
                values[0] = Heap(reader.GetStandaloneSignature(MetadataTokens.StandaloneSignatureHandle(rid)).Signature);
                break;
            case 0x12:
                values[0] = (uint)MetadataTokens.GetRowNumber(reader.GetTypesWithEvents().ElementAt(rid - 1));
                break;
            case 0x14:
                {
                    var row = reader.GetEventDefinition(MetadataTokens.EventDefinitionHandle(rid));
                    Set(values, (uint)row.Attributes, Heap(row.Name), Encode(0, row.Type));
                }
                break;
            case 0x15:
                values[0] = (uint)MetadataTokens.GetRowNumber(reader.GetTypesWithProperties().ElementAt(rid - 1));
                break;
            case 0x17:
                {
                    var row = reader.GetPropertyDefinition(MetadataTokens.PropertyDefinitionHandle(rid));
                    Set(values, (uint)row.Attributes, Heap(row.Name), Heap(row.Signature));
                }
                break;
            case 0x19:
                {
                    var row = reader.GetMethodImplementation(MetadataTokens.MethodImplementationHandle(rid));
                    Set(values, (uint)MetadataTokens.GetRowNumber(row.Type), Encode(7, row.MethodBody), Encode(7, row.MethodDeclaration));
                }
                break;
            case 0x1A:
                values[0] = Heap(reader.GetModuleReference(MetadataTokens.ModuleReferenceHandle(rid)).Name);
                break;
            case 0x1B:
                values[0] = Heap(reader.GetTypeSpecification(MetadataTokens.TypeSpecificationHandle(rid)).Signature);
                break;
            case 0x1E:
                {
                    var entry = reader.GetEditAndContinueLogEntries().ElementAt(rid - 1);
                    Set(values, (uint)MetadataTokens.GetToken(entry.Handle), (uint)entry.Operation);
                }
                break;
            case 0x1F:
                values[0] = (uint)MetadataTokens.GetToken(reader.GetEditAndContinueMapEntries().ElementAt(rid - 1));
                break;
            case 0x20:
                if (rid == 1)
                {
                    var row = reader.GetAssemblyDefinition();
                    Set(values, (uint)row.HashAlgorithm, (uint)row.Version.Major, (uint)row.Version.Minor, (uint)row.Version.Build,
                        (uint)row.Version.Revision, (uint)row.Flags, Heap(row.PublicKey), Heap(row.Name), Heap(row.Culture));
                }
                break;
            case 0x23:
                {
                    var row = reader.GetAssemblyReference(MetadataTokens.AssemblyReferenceHandle(rid));
                    Set(values, (uint)row.Version.Major, (uint)row.Version.Minor, (uint)row.Version.Build, (uint)row.Version.Revision,
                        (uint)row.Flags, Heap(row.PublicKeyOrToken), Heap(row.Name), Heap(row.Culture), Heap(row.HashValue));
                }
                break;
            case 0x26:
                {
                    var row = reader.GetAssemblyFile(MetadataTokens.AssemblyFileHandle(rid));
                    values[1] = Heap(row.Name);
                    values[2] = Heap(row.HashValue);
                }
                break;
            case 0x27:
                {
                    var row = reader.GetExportedType(MetadataTokens.ExportedTypeHandle(rid));
                    values[0] = (uint)row.Attributes;
                    values[2] = Heap(row.Name);
                    values[3] = Heap(row.Namespace);
                    values[4] = Encode(9, row.Implementation);
                }
                break;
            case 0x28:
                {
                    var row = reader.GetManifestResource(MetadataTokens.ManifestResourceHandle(rid));
                    Set(values, (uint)row.Offset, (uint)row.Attributes, Heap(row.Name), Encode(9, row.Implementation));
                }
                break;
            case 0x2A:
                {
                    var row = reader.GetGenericParameter(MetadataTokens.GenericParameterHandle(rid));
                    Set(values, (uint)row.Index, (uint)row.Attributes, Encode(12, row.Parent), Heap(row.Name));
                }
                break;
            case 0x2B:
                {
                    var row = reader.GetMethodSpecification(MetadataTokens.MethodSpecificationHandle(rid));
                    Set(values, Encode(7, row.Method), Heap(row.Signature));
                }
                break;
            case 0x2C:
                {
                    var row = reader.GetGenericParameterConstraint(MetadataTokens.GenericParameterConstraintHandle(rid));
                    Set(values, (uint)MetadataTokens.GetRowNumber(row.Parameter), Encode(0, row.Type));
                }
                break;
            case 0x30:
                {
                    var row = reader.GetDocument(MetadataTokens.DocumentHandle(rid));
                    Set(values, Heap((BlobHandle)row.Name), Heap(row.HashAlgorithm), Heap(row.Hash), Heap(row.Language));
                }
                break;
            case 0x31:
                {
                    var row = reader.GetMethodDebugInformation(MetadataTokens.MethodDebugInformationHandle(rid));
                    Set(values, (uint)MetadataTokens.GetRowNumber(row.Document), Heap(row.SequencePointsBlob));
                }
                break;
            case 0x32:
                {
                    // The variable and constant lists are the row's own columns
                    var row = reader.GetLocalScope(MetadataTokens.LocalScopeHandle(rid));
                    values[0] = (uint)MetadataTokens.GetRowNumber(row.Method);
                    values[1] = (uint)MetadataTokens.GetRowNumber(row.ImportScope);
                    values[4] = (uint)row.StartOffset;
                    values[5] = (uint)row.Length;
                }
                break;
            case 0x33:
                {
                    var row = reader.GetLocalVariable(MetadataTokens.LocalVariableHandle(rid));
                    Set(values, (uint)row.Attributes, (uint)row.Index, Heap(row.Name));
                }
                break;
            case 0x34:
                {
                    var row = reader.GetLocalConstant(MetadataTokens.LocalConstantHandle(rid));
                    Set(values, Heap(row.Name), Heap(row.Signature));
                }
                break;
            case 0x35:
                {
                    var row = reader.GetImportScope(MetadataTokens.ImportScopeHandle(rid));
                    Set(values, (uint)MetadataTokens.GetRowNumber(row.Parent), Heap(row.ImportsBlob));
                }
                break;
            case 0x37:
                {
                    var row = reader.GetCustomDebugInformation(MetadataTokens.CustomDebugInformationHandle(rid));
                    Set(values, Encode(13, row.Parent), Heap(row.Kind), Heap(row.Value));
                }
                break;
        }
        return values;
    }

    // The debug tables' values SRM decodes from their blobs: each document's path, each
    // method's sequence points and each import scope's imports.
    void DebugValues()
    {
        if ((valid & (1UL << 0x30)) != 0)
            foreach (var handle in reader.Documents)
            {
                string name;
                try
                {
                    name = SrmDump.Quoted(reader.GetString(reader.GetDocument(handle).Name));
                }
                catch (BadImageFormatException)
                {
                    name = "unreadable";
                }
                dump[prefix + "Document[" + MetadataTokens.GetRowNumber(handle) + "].name"] = name;
            }
        if ((valid & (1UL << 0x31)) != 0)
            foreach (var handle in reader.MethodDebugInformation)
            {
                var info = reader.GetMethodDebugInformation(handle);
                if (info.SequencePointsBlob.IsNil)
                    continue;
                string points;
                try
                {
                    var text = new StringBuilder("locals 0x" + (info.LocalSignature.IsNil ? 0 : MetadataTokens.GetToken(info.LocalSignature)).ToString("x8") + ";");
                    foreach (var point in info.GetSequencePoints())
                    {
                        text.Append(" IL_").Append(point.Offset.ToString("X4")).Append(" doc ").Append(MetadataTokens.GetRowNumber(point.Document));
                        if (point.IsHidden)
                            text.Append(" hidden;");
                        else
                            text.Append(' ').Append(point.StartLine).Append(':').Append(point.StartColumn)
                                .Append('-').Append(point.EndLine).Append(':').Append(point.EndColumn).Append(';');
                    }
                    points = text.ToString();
                }
                catch (BadImageFormatException)
                {
                    points = "undecodable";
                }
                dump[prefix + "MethodDebugInformation[" + MetadataTokens.GetRowNumber(handle) + "].points"] = points;
            }
        if ((valid & (1UL << 0x35)) != 0)
            foreach (var handle in reader.ImportScopes)
            {
                var scope = reader.GetImportScope(handle);
                if (scope.ImportsBlob.IsNil)
                    continue;
                string imports;
                try
                {
                    imports = string.Join(" ", scope.GetImports().Select(Import));
                }
                catch (BadImageFormatException)
                {
                    imports = "undecodable";
                }
                dump[prefix + "ImportScope[" + MetadataTokens.GetRowNumber(handle) + "].imports"] = imports;
            }
    }

    // An import as the dump writes it: its kind's number, then its alias, assembly, namespace
    // and type, those its kind has.
    string Import(ImportDefinition import)
    {
        var kind = (int)import.Kind;
        var text = new StringBuilder(kind.ToString());
        if (kind >= 4)
            text.Append(" alias ").Append(SrmDump.Quoted(Utf8(import.Alias)));
        if (kind == 2 || kind == 6 || kind == 8)
            text.Append(" assembly 0x").Append(MetadataTokens.GetToken(import.TargetAssembly).ToString("x8"));
        if (kind == 1 || kind == 2 || kind == 4 || kind == 7 || kind == 8)
            text.Append(" namespace ").Append(SrmDump.Quoted(Utf8(import.TargetNamespace)));
        if (kind == 3 || kind == 9)
            text.Append(" type 0x").Append(MetadataTokens.GetToken(import.TargetType).ToString("x8"));
        return text.Append(';').ToString();
    }

    // A blob's bytes as UTF-8, an invalid sequence as U+FFFD.
    string Utf8(BlobHandle handle)
    {
        return Encoding.UTF8.GetString(reader.GetBlobBytes(handle));
    }

    static void Set(uint[] values, params uint[] leading)
    {
        Array.Copy(leading, values, leading.Length);
    }

    static uint Heap(StringHandle handle) { return (uint)MetadataTokens.GetHeapOffset(handle); }
    static uint Heap(BlobHandle handle) { return (uint)MetadataTokens.GetHeapOffset(handle); }
    static uint Heap(GuidHandle handle) { return (uint)MetadataTokens.GetHeapOffset(handle); }

    // The coded index of family `family` that names `handle`'s row.
    static uint Encode(int family, EntityHandle handle)
    {
        var token = MetadataTokens.GetToken(handle);
        if (token == 0)
            return 0;
        var tag = Array.IndexOf(Coded[family], token >> 24);
        if (tag < 0)
            throw new BadImageFormatException("a " + CodedNames[family] + " names table " + (token >> 24));
        return (uint)(((token & 0x00FFFFFF) << TagBits(Coded[family].Length)) | tag);
    }

    // A row as the dump writes it: its columns in an all-four-byte layout, the heap columns as
    // what they name and the rest in hex. MethodDef's RVA, FieldRVA's RVA and
    // ManifestResource's Offset, which the dump compares by what they point at, are left out.
    string Render(int table, uint[] values)
    {
        var columns = Schema[table];
        var parts = new List<string>();
        var run = new StringBuilder();
        var first = table == 0x06 || table == 0x1D || table == 0x28 ? 1 : 0;
        for (var i = first; i < columns.Length; i++)
        {
            if (columns[i].IsHeap)
            {
                if (run.Length > 0)
                {
                    parts.Add(run.ToString());
                    run.Clear();
                }
                parts.Add(Resolve(columns[i].Kind, values[i]));
                continue;
            }
            var width = columns[i].Kind == '1' ? 1 : columns[i].Kind == '2' ? 2 : 4;
            for (var b = 0; b < width; b++)
                run.Append(((values[i] >> (8 * b)) & 0xFF).ToString("x2"));
        }
        if (run.Length > 0)
            parts.Add(run.ToString());
        return string.Join(" ", parts);
    }

    // What a heap index names: a string, a blob's bytes, a GUID.
    string Resolve(char heap, uint value)
    {
        try
        {
            switch (heap)
            {
                case 'S':
                    var text = reader.GetString(MetadataTokens.StringHandle((int)value));
                    return text.Length == 0 ? "\"\"" : text;
                case 'B':
                    return "blob[" + SrmDump.Hex(reader.GetBlobBytes(MetadataTokens.BlobHandle((int)value))) + "]";
                default:
                    if (value == 0)
                        return "null";
                    return "guid[" + reader.GetGuid(MetadataTokens.GuidHandle((int)value)).ToString() + "]";
            }
        }
        catch (Exception error) when (error is BadImageFormatException || error is ArgumentException)
        {
            return (heap == 'S' ? "str#" : heap == 'B' ? "blob#" : "guid#") + value;
        }
    }

    static readonly Dictionary<int, OpCode> OpCodes = typeof(System.Reflection.Emit.OpCodes)
        .GetFields(BindingFlags.Public | BindingFlags.Static)
        .Select(field => (OpCode)field.GetValue(null))
        .Where(code => code.OpCodeType != OpCodeType.Nternal)
        .ToDictionary(code => (int)(ushort)code.Value);

    // A method body: its header's facts, each instruction with branch targets as instruction
    // positions, and its protected regions.
    string Body(int rva)
    {
        MethodBodyBlock body;
        try
        {
            body = pe.GetMethodBody(rva);
        }
        catch (BadImageFormatException)
        {
            return "unreadable";
        }
        var code = body.GetILBytes();
        var offsets = new List<int>();
        var mnemonics = new List<string>();
        var operands = new List<Func<Func<long, string>, string>>();
        var at = 0;
        try
        {
            while (at < code.Length)
            {
                offsets.Add(at);
                int value = code[at++];
                if (value == 0xFE)
                    value = 0xFE00 | code[at++];
                OpCode opcode;
                if (!OpCodes.TryGetValue(value, out opcode))
                    return "undecodable";
                var name = opcode.Name;
                switch (opcode.OperandType)
                {
                    case OperandType.InlineNone:
                        operands.Add(position => "");
                        break;
                    case OperandType.ShortInlineBrTarget:
                        {
                            // A short branch and its long form are one branch
                            name = name.Substring(0, name.Length - 2);
                            var target = at + 1 + (long)(sbyte)code[at];
                            at += 1;
                            operands.Add(position => position(target));
                        }
                        break;
                    case OperandType.InlineBrTarget:
                        {
                            var target = at + 4 + (long)BitConverter.ToInt32(Take(code, at, 4), 0);
                            at += 4;
                            operands.Add(position => position(target));
                        }
                        break;
                    case OperandType.ShortInlineI:
                        {
                            var text = value == 0xFE12 ? Take(code, at, 1)[0].ToString() : ((sbyte)Take(code, at, 1)[0]).ToString();
                            at += 1;
                            operands.Add(position => text);
                        }
                        break;
                    case OperandType.ShortInlineVar:
                        {
                            var text = Take(code, at, 1)[0].ToString();
                            at += 1;
                            operands.Add(position => text);
                        }
                        break;
                    case OperandType.InlineVar:
                        {
                            var text = BitConverter.ToUInt16(Take(code, at, 2), 0).ToString();
                            at += 2;
                            operands.Add(position => text);
                        }
                        break;
                    case OperandType.InlineI:
                        {
                            var text = BitConverter.ToInt32(Take(code, at, 4), 0).ToString();
                            at += 4;
                            operands.Add(position => text);
                        }
                        break;
                    case OperandType.InlineI8:
                        {
                            var text = BitConverter.ToInt64(Take(code, at, 8), 0).ToString();
                            at += 8;
                            operands.Add(position => text);
                        }
                        break;
                    case OperandType.ShortInlineR:
                        {
                            var text = "0x" + BitConverter.ToUInt32(Take(code, at, 4), 0).ToString("x8");
                            at += 4;
                            operands.Add(position => text);
                        }
                        break;
                    case OperandType.InlineR:
                        {
                            var text = "0x" + BitConverter.ToUInt64(Take(code, at, 8), 0).ToString("x16");
                            at += 8;
                            operands.Add(position => text);
                        }
                        break;
                    case OperandType.InlineSwitch:
                        {
                            var count = BitConverter.ToUInt32(Take(code, at, 4), 0);
                            Take(code, at, 4 + 4 * (long)count);
                            var next = at + 4 + 4 * (long)count;
                            var targets = new List<long>();
                            for (var i = 0; i < count; i++)
                                targets.Add(next + BitConverter.ToInt32(code, at + 4 + 4 * i));
                            at = (int)next;
                            operands.Add(position => string.Join(",", targets.Select(position)));
                        }
                        break;
                    default:
                        {
                            var token = BitConverter.ToInt32(Take(code, at, 4), 0);
                            at += 4;
                            var text = (token >> 24) == 0x70 ? UserString(token) : "0x" + token.ToString("x8");
                            operands.Add(position => text);
                        }
                        break;
                }
                mnemonics.Add(name);
            }
        }
        catch (IndexOutOfRangeException)
        {
            return "undecodable";
        }
        Func<long, string> where = offset =>
        {
            var index = offsets.BinarySearch((int)Math.Max(int.MinValue, Math.Min(int.MaxValue, offset)));
            if (index >= 0 && offsets[index] == offset)
                return "#" + index;
            return offset == code.Length ? "end" : "@0x" + unchecked((ulong)offset).ToString("x");
        };
        var listing = new StringBuilder();
        listing.Append("max stack ").Append(body.MaxStack).Append(", init locals ")
            .Append(body.LocalVariablesInitialized ? "true" : "false").Append(", locals 0x")
            .Append((body.LocalSignature.IsNil ? 0 : MetadataTokens.GetToken(body.LocalSignature)).ToString("x8")).Append(';');
        for (var i = 0; i < mnemonics.Count; i++)
        {
            listing.Append(' ').Append(mnemonics[i]);
            var operand = operands[i](where);
            if (operand.Length > 0)
                listing.Append(' ').Append(operand);
            listing.Append(';');
        }
        foreach (var region in body.ExceptionRegions)
        {
            listing.Append(" handler ").Append((int)region.Kind)
                .Append(" try ").Append(where(region.TryOffset)).Append("..").Append(where((long)region.TryOffset + region.TryLength))
                .Append(" handler ").Append(where(region.HandlerOffset)).Append("..").Append(where((long)region.HandlerOffset + region.HandlerLength));
            if (region.Kind == ExceptionRegionKind.Catch)
                listing.Append(" class 0x").Append(MetadataTokens.GetToken(region.CatchType).ToString("x8"));
            else if (region.Kind == ExceptionRegionKind.Filter)
                listing.Append(" filter ").Append(where(region.FilterOffset));
            listing.Append(';');
        }
        return listing.ToString();
    }

    // `count` bytes of `code` at `at`, or the end of the code they run past.
    static byte[] Take(byte[] code, int at, long count)
    {
        if (at + count > code.Length)
            throw new IndexOutOfRangeException();
        var bytes = new byte[count];
        Array.Copy(code, at, bytes, 0, count);
        return bytes;
    }

    string UserString(int token)
    {
        try
        {
            return SrmDump.Quoted(reader.GetUserString(MetadataTokens.UserStringHandle(token & 0x00FFFFFF)));
        }
        catch (Exception error) when (error is BadImageFormatException || error is ArgumentException)
        {
            return "us#0x" + (token & 0x00FFFFFF).ToString("x");
        }
    }

    // A field's initial data: as many bytes as its type takes, when its signature says.
    string FieldData(uint rva, uint field)
    {
        try
        {
            var definition = reader.GetFieldDefinition(MetadataTokens.FieldDefinitionHandle((int)field));
            var pointer = pe.PEHeaders.PEHeader.Magic == PEMagic.PE32Plus ? 8 : 4;
            var size = definition.DecodeSignature(new Sizes(reader, pointer), null);
            if (size < 0)
                return "unreadable";
            var data = rva == 0 ? null : ImageBytes((int)rva, size);
            return data == null ? "unreadable" : SrmDump.Hex(data);
        }
        catch (Exception error) when (error is BadImageFormatException || error is ArgumentException || error is InvalidOperationException)
        {
            return "unreadable";
        }
    }

    // The `size` bytes the loaded image holds at `rva`, or null when they are not all the
    // image's: SRM gives a section's file data from `rva` within its VirtualSize, and the loader
    // zeroes the rest of the VirtualSize.
    byte[] ImageBytes(int rva, long size)
    {
        var section = pe.PEHeaders.SectionHeaders.FirstOrDefault(s =>
            rva >= s.VirtualAddress && rva - (long)s.VirtualAddress < (s.VirtualSize == 0 ? s.SizeOfRawData : s.VirtualSize));
        if (section.Name == null)
            return null;
        var extent = section.VirtualSize == 0 ? section.SizeOfRawData : section.VirtualSize;
        if (rva - (long)section.VirtualAddress + size > extent)
            return null;
        var backed = pe.GetSectionData(rva);
        var bytes = new byte[size];
        var copied = (int)Math.Min(size, backed.Length);
        backed.GetContent(0, copied).CopyTo(0, bytes, 0, copied);
        // What the file lacks of the raw data is no byte at all
        var raw = Math.Min(section.SizeOfRawData, extent) - (rva - (long)section.VirtualAddress);
        return copied < Math.Min(size, raw) ? null : bytes;
    }

    // An embedded resource, by name: its length and its content's hash.
    void Resource(uint[] row)
    {
        var directory = pe.PEHeaders.CorHeader.ResourcesDirectory.RelativeVirtualAddress;
        // A null Implementation names the assembly's own resources
        if ((row[3] >> 2) != 0 || directory == 0)
            return;
        var name = Resolve('S', row[2]);
        try
        {
            var at = directory + (int)row[0];
            var prefix = ImageBytes(at, 4);
            var data = prefix == null ? null : ImageBytes(at + 4, BitConverter.ToUInt32(prefix, 0));
            dump["Resource[" + name + "]"] = data == null
                ? "unreadable"
                : data.Length + " bytes, sha256 " + SrmDump.Sha256(data);
        }
        catch (Exception error) when (error is BadImageFormatException || error is ArgumentException)
        {
            dump["Resource[" + name + "]"] = "unreadable";
        }
    }
}

// The size of a field's type, as the dump counts it (-1: not known from the signature): a
// primitive's, a value type's declared ClassLayout size, an array's with every dimension sized.
sealed class Sizes : ISignatureTypeProvider<long, object>
{
    readonly MetadataReader reader;
    readonly int pointer;

    public Sizes(MetadataReader reader, int pointer)
    {
        this.reader = reader;
        this.pointer = pointer;
    }

    public long GetPrimitiveType(PrimitiveTypeCode code)
    {
        switch (code)
        {
            case PrimitiveTypeCode.Boolean:
            case PrimitiveTypeCode.SByte:
            case PrimitiveTypeCode.Byte:
                return 1;
            case PrimitiveTypeCode.Char:
            case PrimitiveTypeCode.Int16:
            case PrimitiveTypeCode.UInt16:
                return 2;
            case PrimitiveTypeCode.Int32:
            case PrimitiveTypeCode.UInt32:
            case PrimitiveTypeCode.Single:
                return 4;
            case PrimitiveTypeCode.Int64:
            case PrimitiveTypeCode.UInt64:
            case PrimitiveTypeCode.Double:
                return 8;
            case PrimitiveTypeCode.IntPtr:
            case PrimitiveTypeCode.UIntPtr:
                return pointer;
            default:
                return -1;
        }
    }

    public long GetTypeFromDefinition(MetadataReader metadata, TypeDefinitionHandle handle, byte rawTypeKind)
    {
        // A value type declares its size in ClassLayout
        if (rawTypeKind != 0x11)
            return -1;
        var layout = metadata.GetTypeDefinition(handle).GetLayout();
        return layout.IsDefault ? -1 : (long)(uint)layout.Size;
    }

    public long GetArrayType(long element, ArrayShape shape)
    {
        if (element < 0 || shape.Sizes.Length < shape.Rank)
            return -1;
        var size = element;
        try
        {
            foreach (var dimension in shape.Sizes.Take(shape.Rank))
                size = checked(size * dimension);
        }
        catch (OverflowException)
        {
            return -1;
        }
        return size;
    }

    public long GetTypeFromReference(MetadataReader metadata, TypeReferenceHandle handle, byte rawTypeKind) { return -1; }
    public long GetTypeFromSpecification(MetadataReader metadata, object context, TypeSpecificationHandle handle, byte rawTypeKind) { return -1; }
    public long GetSZArrayType(long element) { return -1; }
    public long GetByReferenceType(long element) { return -1; }
    public long GetPointerType(long element) { return -1; }
    public long GetPinnedType(long element) { return -1; }
    public long GetModifiedType(long modifier, long unmodified, bool isRequired) { return unmodified; }
    public long GetFunctionPointerType(MethodSignature<long> signature) { return -1; }
    public long GetGenericInstantiation(long generic, ImmutableArray<long> arguments) { return -1; }
    public long GetGenericMethodParameter(object context, int index) { return -1; }
    public long GetGenericTypeParameter(object context, int index) { return -1; }
}
