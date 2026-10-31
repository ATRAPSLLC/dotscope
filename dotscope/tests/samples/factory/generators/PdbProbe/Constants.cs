// LocalConstant rows: a constant local of every type a C# constant can have, so each value
// encoding of the LocalConstantSig blob appears.
using System;

namespace PdbProbe
{
    public enum Colour : short
    {
        Red = -2,
        Green = 7,
    }

    public static class Constants
    {
        public static int Sum()
        {
            const bool flag = true;
            const char letter = 'Z';
            const sbyte tiny = -8;
            const byte small = 200;
            const short shortValue = -300;
            const ushort ushortValue = 60000;
            const int intValue = -123456;
            const uint uintValue = 4000000000;
            const long longValue = -9000000000;
            const ulong ulongValue = 18000000000000000000;
            const float single = 1.5f;
            const double real = -2.25;
            const decimal money = 12345.6789m;
            const decimal negative = -0.001m;
            const string text = "constant text";
            const string? nothing = null;
            const object? none = null;
            const Colour colour = Colour.Green;
            const nint native = -5;
            const nuint unative = 5;
            int sum = (flag ? 1 : 0) + letter + tiny + small + shortValue + ushortValue + intValue;
            sum += (int)(uintValue % 7) + (int)(longValue % 7) + (int)(ulongValue % 7);
            sum += (int)single + (int)real + (int)money + (int)negative + text.Length;
            sum += nothing is null ? 1 : 0;
            sum += none is null ? 1 : 0;
            sum += (int)colour + (int)native + (int)unative;
            return sum;
        }

        // A constant whose type is a type parameter's instantiation and a constant of a
        // type from another assembly
        public static int Generic<T>(T value)
        {
            const StringComparison comparison = StringComparison.Ordinal;
            return value is null ? 0 : (int)comparison;
        }
    }
}
