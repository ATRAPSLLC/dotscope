// Sequence points across documents within one method (#line naming another file), hidden
// sequence points (#line hidden) and span-mapped lines (#line (start) - (end)).
namespace PdbProbe
{
    public static class Lines
    {
        public static int Mapped(int value)
        {
            int result = value;
#line 500 "Generated/Mapped.razor"
            result += 2;
            result *= 3;
#line hidden
            result -= 1;
#line (10, 5) - (12, 20) 3 "Generated/Spans.razor"
            result += 4;
#line default
            return result;
        }
    }
}
