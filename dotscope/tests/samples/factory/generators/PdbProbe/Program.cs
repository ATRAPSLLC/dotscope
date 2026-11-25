// Entry point: calls every probe so each method has run-time meaning, and the PDB its
// EntryPoint. The files beside it each produce one group of PDB records.
extern alias probelib;

using System;
using System.Threading.Tasks;

namespace PdbProbe
{
    public static class Program
    {
        public static async Task<int> Main(string[] args)
        {
            int total = Constants.Sum();
            total += Scopes.Nested(args.Length);
            total += await Async.Compute(3);
            foreach (int value in Async.Iterate(2))
            {
                total += value;
            }
            await foreach (int value in Async.Stream(2))
            {
                total += value;
            }
            total += Locals.DynamicAndTuples();
            total += Lines.Mapped(1);
            total += new Primary(4, "four").Length();
            total += Deep.Nested.Value();
            Console.WriteLine(total);
            return 0;
        }
    }
}
