// Rewrites `[Assembly]Namespace.Type` references in IL text (or C# source holding IL text)
// so that each names the .NET Framework assembly that defines the type, as reflection on
// the running .NET Framework reports it.
//
//   IlRetarget <file>
//
// IL written against .NET (Core) names reference assemblies such as System.Runtime or
// System.Collections, which do not exist on the .NET Framework, where the same types live
// in mscorlib, System or System.Core. A reference whose type no candidate assembly defines
// is reported and the file is left unchanged, with exit code 1.
//
// In C# source, the lines between `#if DOTNETCORE` and its `#else` or `#endif` are left as
// they are: they hold the .NET (Core) forms, which a .NET Framework build does not compile.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.RegularExpressions;

static class Program
{
    // The .NET Framework assemblies a reference may be moved to, in the order they are tried.
    // Each is named by a type it defines: a GAC assembly does not load by its simple name.
    static readonly Assembly[] Candidates =
    {
        typeof(object).Assembly,                        // mscorlib
        typeof(Uri).Assembly,                           // System
        typeof(Enumerable).Assembly,                    // System.Core
        typeof(System.Drawing.Point).Assembly,          // System.Drawing
        typeof(System.Xml.XmlDocument).Assembly,        // System.Xml
        typeof(System.Data.DataSet).Assembly,           // System.Data
    };

    // `[Assembly]Type`, where Type is a dotted name with optional generic arity and `/`
    // nesting, as ildasm writes it.
    static readonly Regex Reference =
        new Regex(@"\[(?<asm>[A-Za-z][A-Za-z0-9.]*)\](?<type>[A-Za-z_][A-Za-z0-9_.`]*(?:/[A-Za-z_][A-Za-z0-9_`]*)*)");

    static int Main(string[] args)
    {
        if (args.Length != 1)
        {
            Console.Error.WriteLine("usage: IlRetarget <file>");
            return 2;
        }
        var lines = File.ReadAllLines(args[0]);
        var unresolved = new SortedSet<string>();
        var moved = new SortedDictionary<string, int>();
        var core = false;
        for (var i = 0; i < lines.Length; i++)
        {
            var directive = lines[i].Trim();
            if (directive.StartsWith("#if DOTNETCORE", StringComparison.Ordinal))
            {
                core = true;
            }
            else if (core && (directive.StartsWith("#else", StringComparison.Ordinal)
                           || directive.StartsWith("#endif", StringComparison.Ordinal)))
            {
                core = false;
            }
            else if (!core)
            {
                lines[i] = Retarget(lines[i], moved, unresolved);
            }
        }
        foreach (var entry in moved)
        {
            Console.WriteLine($"{entry.Key}: {entry.Value}");
        }
        if (unresolved.Count > 0)
        {
            Console.Error.WriteLine("no .NET Framework assembly defines:");
            foreach (var reference in unresolved)
            {
                Console.Error.WriteLine("  " + reference);
            }
            return 1;
        }
        File.WriteAllLines(args[0], lines);
        return 0;
    }

    static string Retarget(string line, IDictionary<string, int> moved, ISet<string> unresolved) =>
        Reference.Replace(line, match =>
        {
            var assembly = match.Groups["asm"].Value;
            var type = match.Groups["type"].Value;
            var defining = DefiningAssembly(type.Replace('/', '+'));
            if (defining == null)
            {
                // Not a framework type (the IL's own types carry no assembly prefix), unless
                // its reference names an assembly the framework does not have.
                if (Candidates.All(c => c.GetName().Name != assembly) && LooksLikeFramework(assembly))
                {
                    unresolved.Add(match.Value);
                }
                return match.Value;
            }
            if (defining == assembly)
            {
                return match.Value;
            }
            var key = assembly + " -> " + defining;
            moved[key] = moved.TryGetValue(key, out var n) ? n + 1 : 1;
            return "[" + defining + "]" + type;
        });

    static string DefiningAssembly(string type)
    {
        foreach (var candidate in Candidates)
        {
            var found = candidate.GetType(type, false);
            if (found != null)
            {
                return found.Assembly.GetName().Name;
            }
        }
        return null;
    }

    static bool LooksLikeFramework(string assembly) =>
        assembly == "System" || assembly.StartsWith("System.", StringComparison.Ordinal)
        || assembly == "mscorlib" || assembly == "netstandard";
}
