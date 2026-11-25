// Stands in for the Windows SDK's ildasm.exe, which JIEJIE.NET's .NET Framework build runs
// to disassemble its input and which is not redistributable.
//
// It runs Microsoft's standalone ildasm (`ildasm.real.exe` beside it, from the
// runtime.win-x64.Microsoft.NETCore.ILDAsm package) with the same arguments, less the two
// it does not accept: `/forward` (forward class declarations, which ilasm does not need)
// and `/nobar` (no progress bar). The IL it writes is otherwise the same.

using System;
using System.Diagnostics;
using System.IO;
using System.Linq;

static class Program
{
    static int Main(string[] args)
    {
        var real = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ildasm.real.exe");
        var kept = args.Where(a => !a.Equals("/forward", StringComparison.OrdinalIgnoreCase)
                                && !a.Equals("/nobar", StringComparison.OrdinalIgnoreCase));
        var info = new ProcessStartInfo(real, string.Join(" ", kept.Select(Quote)))
        {
            UseShellExecute = false,
        };
        using (var process = Process.Start(info))
        {
            process.WaitForExit();
            return process.ExitCode;
        }
    }

    static string Quote(string argument) =>
        argument.IndexOf(' ') < 0 && argument.IndexOf('"') < 0
            ? argument
            : "\"" + argument.Replace("\"", "\\\"") + "\"";
}
