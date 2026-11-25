// A document in a nested directory, for a DocumentName of several parts, and types with no
// method bodies for the TypeDefinitionDocuments record.
namespace PdbProbe.Deep
{
    public interface IMarker
    {
    }

    public enum Shade
    {
        Light,
        Dark,
    }

    public static class Nested
    {
        public static int Value() => (int)Shade.Dark + 1;
    }
}
