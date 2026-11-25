// Reads <directory>/<baseName>.resources through the runtime's ResourceManager, which looks
// each name up by its hash, and prints every name it is given with the value it finds:
// "<name>\t<type>:<value>", or "<name>\t<missing>".
//
// Usage: mono ReadResources.exe <directory> <baseName> <name>...
using System;
using System.Globalization;
using System.IO;
using System.Resources;
using System.Text;

static class ReadResources
{
    static int Main(string[] args)
    {
        var manager = ResourceManager.CreateFileBasedResourceManager(args[1], args[0], null);
        var output = new StringBuilder();
        for (int i = 2; i < args.Length; i++)
        {
            object value = manager.GetObject(args[i], CultureInfo.InvariantCulture);
            output.Append(args[i]).Append('\t').Append(Describe(value)).Append('\n');
        }
        var stdout = Console.OpenStandardOutput();
        var bytes = Encoding.UTF8.GetBytes(output.ToString());
        stdout.Write(bytes, 0, bytes.Length);
        return 0;
    }

    static string Describe(object value)
    {
        if (value == null)
            return "<missing>";
        if (value is byte[] bytes)
            return "Byte[]:" + BitConverter.ToString(bytes);
        if (value is Stream stream)
        {
            var copy = new MemoryStream();
            stream.CopyTo(copy);
            return "Stream:" + BitConverter.ToString(copy.ToArray());
        }
        if (value is string text)
            return "String:" + text.Replace("\\", "\\\\").Replace("\t", "\\t").Replace("\n", "\\n");
        return value.GetType().Name + ":" + Convert.ToString(value, CultureInfo.InvariantCulture);
    }
}
