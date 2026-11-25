// StateMachineMethod rows (async, iterator and async iterator kickoff and MoveNext methods),
// the StateMachineHoistedLocalScopes, EncStateMachineStateMap and AsyncMethodSteppingInformation
// records, and lambdas and closures for EncLambdaAndClosureMap.
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace PdbProbe
{
    public static class Async
    {
        public static async Task<int> Compute(int count)
        {
            int total = 0;
            for (int index = 0; index < count; index++)
            {
                int before = total;
                await Task.Yield();
                total = before + index;
            }
            int captured = total;
            Func<int, int> add = value => value + captured;
            Func<int> twice = () => add(captured);
            return twice();
        }

        public static IEnumerable<int> Iterate(int count)
        {
            for (int index = 0; index < count; index++)
            {
                int doubled = index * 2;
                yield return doubled;
            }
        }

        public static async IAsyncEnumerable<int> Stream(int count)
        {
            for (int index = 0; index < count; index++)
            {
                int value = index + 1;
                await Task.Yield();
                yield return value;
            }
        }
    }
}
