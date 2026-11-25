// Prints one value read from each metadata heap, one line per heap:
//
//   strings=<this type's name>      #Strings
//   us=<a string literal>           #US
//   blob=<an attribute argument>    #Blob
//   guid=<the module's MVID>        #GUID
//
// MetadataVariants adds a second header of one heap's name, pointing at a copy of that
// heap with its marker changed, so the line for that heap says which header the CLR read.

using System;
using System.ComponentModel;
using System.Reflection;

[Description("BlobMarker")]
static class StringsMarker
{
    static void Main()
    {
        Console.WriteLine("strings=" + typeof(StringsMarker).Name);
        Console.WriteLine("us=" + "UserStringMarker");
        var attribute = (DescriptionAttribute)typeof(StringsMarker)
            .GetCustomAttribute(typeof(DescriptionAttribute));
        Console.WriteLine("blob=" + attribute.Description);
        Console.WriteLine("guid=" + typeof(StringsMarker).Module.ModuleVersionId);
    }
}
