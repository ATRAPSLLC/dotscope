using System;

// The input of the section layout experiments (see SectionLayouts), built with Mono's `mcs`,
// whose headers leave room for the section the experiments add. Prints the 32 bytes of `A`, which the compiler stores as field data at an RVA, and the
// result of `F`, whose body is three bytes. SectionLayouts moves both into a section it lays
// out, so the output says what the runtime reads there, or which exception it raises.
static class Program
{
    static readonly byte[] A =
    {
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
        0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
    };

    static int F() => 7;

    static void Main()
    {
        try { Console.WriteLine("A=" + BitConverter.ToString(A)); }
        catch (Exception e) { Console.WriteLine("A!" + Innermost(e)); }
        try { Console.WriteLine("F=" + F()); }
        catch (Exception e) { Console.WriteLine("F!" + Innermost(e)); }
    }

    static string Innermost(Exception e)
    {
        while (e.InnerException != null)
            e = e.InnerException;
        return e.GetType().Name;
    }
}
