using System;
using System.IO;
using System.Linq;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;

// Writes the section layout experiments: SectionLayouts <SectionProbe.exe> <output dir>.
//
// Each experiment is the probe with one section added, `.probe`, whose header states a
// VirtualSize, a SizeOfRawData and a PointerToRawData, and whose file bytes are a pattern that
// names each byte's offset in the section (k ^ (k >> 8) ^ 0x5A). The probe's field data `A` and
// the body of its method `F` are moved into the section, so what the probe prints on a runtime
// says which bytes that runtime reads at an RVA of that layout:
//
//   A=<32 bytes>     the pattern (the file's bytes), or zeros
//   A!<exception>    the runtime refused the data
//   F=7              the runtime ran the body
//   F!<exception>    it refused the body
//
// and no output at all, or a load error, means it refused the image.
static class Program
{
    // name, VirtualSize, SizeOfRawData in the file, SizeOfRawData in the header, how far the
    // header's PointerToRawData is past the bytes, A's offset in the section (or its RVA in
    // the headers), F's offset in the section
    static readonly (string Name, int VirtualSize, int Raw, int HeaderRaw, int PointerDelta, int A, bool AInHeaders, int F)[] Experiments =
    {
        ("inside", 0x400, 0x400, 0x400, 0, 0x100, false, 0x200),
        ("data_past_virtual_size", 0x100, 0x400, 0x400, 0, 0x180, false, 0x80),
        ("data_past_virtual_size_next_page", 0x100, 0x1400, 0x1400, 0, 0x1180, false, 0x80),
        ("data_straddles_virtual_size", 0x100, 0x400, 0x400, 0, 0xF0, false, 0x80),
        ("body_past_virtual_size", 0x100, 0x400, 0x400, 0, 0x40, false, 0x280),
        ("body_straddles_virtual_size", 0x101, 0x400, 0x400, 0, 0x40, false, 0xFF),
        ("zero_fill", 0x1000, 0x200, 0x200, 0, 0x300, false, 0x100),
        ("data_straddles_raw_end", 0x1000, 0x200, 0x200, 0, 0x1F0, false, 0x100),
        ("header_rva", 0x400, 0x400, 0x400, 0, 0x100, true, 0x200),
        ("virtual_size_zero", 0, 0x400, 0x400, 0, 0x180, false, 0x80),
        ("pointer_unaligned", 0x400, 0x400, 0x200, 0x10, 0x100, false, 0x80),
        ("raw_past_file", 0x1000, 0x400, 0x800, 0, 0x100, false, 0x80),
    };

    static void Main(string[] args)
    {
        var input = File.ReadAllBytes(args[0]);
        Directory.CreateDirectory(args[1]);
        foreach (var experiment in Experiments)
        {
            var output = Lay(input, experiment);
            File.WriteAllBytes(Path.Combine(args[1], experiment.Name + ".exe"), output);
            Console.Error.WriteLine($"sections: {experiment.Name}");
        }
    }

    static byte[] Lay(byte[] input, (string Name, int VirtualSize, int Raw, int HeaderRaw, int PointerDelta, int A, bool AInHeaders, int F) e)
    {
        using var pe = new PEReader(new MemoryStream(input));
        var reader = pe.GetMetadataReader();
        var headers = pe.PEHeaders;
        var metadata = headers.MetadataStartOffset;
        var fieldRvaRow = metadata + reader.GetTableMetadataOffset(TableIndex.FieldRva);
        var f = reader.MethodDefinitions.Single(m => reader.GetString(reader.GetMethodDefinition(m).Name) == "F");
        var methodRow = metadata + reader.GetTableMetadataOffset(TableIndex.MethodDef)
            + (MetadataTokens.GetRowNumber(f) - 1) * reader.GetTableRowSize(TableIndex.MethodDef);
        var bodyRva = reader.GetMethodDefinition(f).RelativeVirtualAddress;
        var body = pe.GetSectionData(bodyRva).GetContent(0, pe.GetMethodBody(bodyRva).Size).ToArray();

        var raw = new byte[e.Raw];
        for (var k = 0; k < raw.Length; k++)
            raw[k] = (byte)(k ^ (k >> 8) ^ 0x5A);
        body.CopyTo(raw, e.F);

        var table = headers.PEHeaderStartOffset + headers.CoffHeader.SizeOfOptionalHeader;
        var count = headers.CoffHeader.NumberOfSections;
        var header = table + count * 40;
        if (header + 40 > headers.PEHeader.SizeOfHeaders)
            throw new InvalidOperationException("no room in the headers for another section");
        var va = headers.PEHeader.SizeOfImage;
        var alignment = headers.PEHeader.SectionAlignment;

        var output = input.Concat(raw).ToArray();
        ".probe\0\0".Select(c => (byte)c).ToArray().CopyTo(output, header);
        Put(output, header + 8, e.VirtualSize);
        Put(output, header + 12, va);
        Put(output, header + 16, e.HeaderRaw);
        Put(output, header + 20, input.Length + e.PointerDelta);
        Put(output, header + 36, 0x60000020);
        BitConverter.GetBytes((ushort)(count + 1)).CopyTo(output, headers.CoffHeaderStartOffset + 2);
        var extent = Math.Max(e.VirtualSize, e.HeaderRaw);
        Put(output, headers.PEHeaderStartOffset + 56, va + (extent + alignment - 1) / alignment * alignment);
        Put(output, fieldRvaRow, e.AInHeaders ? e.A : va + e.A);
        Put(output, methodRow, va + e.F);
        return output;
    }

    static void Put(byte[] bytes, int at, int value) => BitConverter.GetBytes(value).CopyTo(bytes, at);
}
