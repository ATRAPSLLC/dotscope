// LocalScope rows nested several deep, LocalVariable rows in each, and an ImportScope with
// every import kind C# writes: namespace, type (using static), namespace alias, type alias,
// extern alias, and a namespace of an extern-aliased assembly.
extern alias probelib;

using System;
using System.Collections.Generic;
using static System.Math;
using Text = System.Text;
using IntList = System.Collections.Generic.List<int>;
using Shapes = probelib::ProbeLib.Shapes;
using probelib::ProbeLib.Shapes;

namespace PdbProbe
{
    public static class Scopes
    {
        public static int Nested(int seed)
        {
            int outer = seed + 1;
            var list = new IntList { outer };
            {
                int middle = outer * 2;
                list.Add(middle);
                {
                    var builder = new Text.StringBuilder();
                    builder.Append(middle);
                    int inner = Max(builder.Length, middle);
                    list.Add(inner);
                    for (int index = 0; index < 2; index++)
                    {
                        int loop = index + inner;
                        list.Add(loop);
                    }
                }
            }
            var square = new Shapes.Square(outer);
            var another = new Square(2);
            Dictionary<string, int> map = new() { ["area"] = square.Area() + another.Area() };
            return list.Count + map["area"];
        }
    }
}
