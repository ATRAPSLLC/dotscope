// Loads an assembly into CoreCLR and runs its entry point, so the factory's oracle can check
// a sample against CoreCLR's metadata reader as well as the .NET Framework's.
//
//   CoreClrHost <sample.exe>
//
// The sample's own output goes to stdout. Exit code 0 means the entry point returned; 1
// means the load or the run threw, with the exception on stderr.

using System.Reflection;
using System.Runtime.Loader;

if (args.Length != 1)
{
    Console.Error.WriteLine("usage: CoreClrHost <sample.exe>");
    return 2;
}

try
{
    var assembly = AssemblyLoadContext.Default.LoadFromAssemblyPath(Path.GetFullPath(args[0]));
    var entry = assembly.EntryPoint
        ?? throw new InvalidOperationException("the assembly has no entry point");
    var arguments = entry.GetParameters().Length == 0 ? null : new object[] { Array.Empty<string>() };
    var result = entry.Invoke(null, arguments);
    Console.Out.Flush();
    return result is int code ? code : 0;
}
catch (Exception e)
{
    Console.Out.Flush();
    Console.Error.WriteLine(e is TargetInvocationException { InnerException: { } inner } ? inner : e);
    return 1;
}
