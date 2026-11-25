// PrimaryConstructorInformation: a class with a primary constructor whose parameters the body
// captures, and a record struct with one.
namespace PdbProbe
{
    public sealed class Primary(int size, string name)
    {
        public int Length() => size + name.Length;
    }

    public readonly record struct Point(int X, int Y);
}
