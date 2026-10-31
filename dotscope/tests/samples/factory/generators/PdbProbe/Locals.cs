// DynamicLocalVariables and TupleElementNames records: dynamic locals and constants, and
// locals of named tuple types, nested and within generic arguments.
using System;
using System.Collections.Generic;

namespace PdbProbe
{
    public static class Locals
    {
        public static int DynamicAndTuples()
        {
            dynamic value = 3;
            dynamic[] values = { 1, "two" };
            List<dynamic> list = new() { value };
            const dynamic? nothing = null;
            (int first, string second) pair = (1, "x");
            (int a, (string b, int c) nested) deep = (2, ("y", 3));
            List<(int key, string name)> named = new() { (4, "z") };
            int total = (int)value + values.Length + list.Count + (nothing is null ? 1 : 0);
            return total + pair.first + deep.nested.c + named[0].key;
        }
    }
}
