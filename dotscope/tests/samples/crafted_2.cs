// Source of crafted_2.exe. Requires .NET Core 3.0.

using System;
using System.Collections;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Reflection;
using System.Reflection.Emit;
using System.Security;
using System.Security.Permissions;
using System.Runtime.CompilerServices;
using System.Runtime.Serialization;
using System.ComponentModel;
using System.Linq;
using System.IO;
using System.Diagnostics;
using System.Text;

// This attribute will be stored in the Assembly table
[assembly: AssemblyTitle("MetadataTestCases")]
[assembly: AssemblyDescription("Test assembly for CIL metadata reverse engineering")]
[assembly: AssemblyVersion("1.2.3.4")]
[assembly: AssemblyCulture("")]

// Security permissions (DeclSecurity table)
[assembly: SecurityPermission(SecurityAction.RequestMinimum, Assertion = true)]
[assembly: FileIOPermission(SecurityAction.RequestMinimum, Read = @"C:\TestData")]

// Custom attribute with various parameter types
[assembly: MetadataTestAttribute(42, "Test", PropertyValue = DateTime.MinValue)]

// Module-level attributes
[module: CLSCompliant(false)]
[module: DefaultCharSet(CharSet.Unicode)]

// Custom attribute definition (will go in the various metadata tables)
[AttributeUsage(AttributeTargets.All, AllowMultiple = true)]
public sealed class MetadataTestAttribute : Attribute
{
    // Fields will populate Field table
    private int _intValue;
    public readonly string StringValue;

    // Constructor parameters will be in the Param table
    public MetadataTestAttribute(int intValue, string stringValue)
    {
        _intValue = intValue;
        StringValue = stringValue;
    }

    // Property will generate accessor methods
    public DateTime PropertyValue { get; set; }

    // Will populate the Constant table with default param value
    public bool BoolProperty { get; set; } = true;
}

// Global methods (MethodDef at module level)
public static class Globals
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    public static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("user32.dll")]
    public static extern bool MessageBox(IntPtr hWnd, string text, string caption, uint type);
}

// Interface definitions (TypeDef with Interface flags)
public interface IBaseInterface
{
    void Method1();
    int Property1 { get; set; }
}

public interface IDerivedInterface : IBaseInterface
{
    void Method2<T>(T param) where T : struct;
    event EventHandler Event1;
}

// Delegate types (TypeDef with special class semantics)
public delegate void SimpleDelegate(int x);

public delegate TResult GenericDelegate<T, TResult>(T input) where T : class;

// Enum types (ValueType with Enum semantics)
[Flags]
public enum TestEnum : long
{
    None = 0,
    Value1 = 1,
    Value2 = 2,
    Value3 = 4,
    All = Value1 | Value2 | Value3
}

// Struct types (ValueType in metadata)
[StructLayout(LayoutKind.Explicit, Size = 16)]
public struct StructWithExplicitLayout
{
    [FieldOffset(0)]
    public int Field1;

    [FieldOffset(4)]
    public long Field2;

    [FieldOffset(0)]
    public double Overlay;
}

// Generic struct with constraints
public struct GenericStruct<T, U>
    where T : struct
    where U : class, new()
{
    public T Field1;
    public U Field2;

    public void Method(T t, U u) { }
}

// Base class with virtual methods (for testing method overrides)
[Serializable]
public abstract class BaseClass
{
    // Static field with RVA (embedded data)
    private static readonly byte[] StaticData = new byte[] { 1, 2, 3, 4, 5 };

    // Virtual method (for MethodImpl table)
    public virtual void VirtualMethod() { }

    // Abstract method (for MethodImpl table)
    public abstract void AbstractMethod();

    // Method with complex signature for testing Param and ParamType tables
    [Obsolete("For testing")]
    public virtual int ComplexMethod(
        int normalParam,
        ref string refParam,
        out int outParam,
        [Optional] object optionalParam,
        params object[] paramsArray)
    {
        outParam = 42;
        return normalParam;
    }

    // Protected method for testing method access flags
    protected virtual void ProtectedMethod() { }

    // Static constructor (special name)
    static BaseClass()
    {
        Console.WriteLine("Static constructor");
    }

    // Indexer (special method with parameters)
    public virtual object this[int index] => null;
}

// Derived class with method implementations (for MethodImpl table)
[MetadataTest(100, "Derived Class", PropertyValue = DateTime.Now)]
public class DerivedClass : BaseClass, IDerivedInterface
{
    // Field with marshaling information
    [MarshalAs(UnmanagedType.LPWStr)]
    private string _marshaledField;

    // Private nested type (for NestedClass table)
    private class NestedClass
    {
        public void NestedMethod() { }
    }

    // Nested enum (another NestedClass entry)
    protected enum NestedEnum
    {
        One,
        Two
    }

    // Generic nested class with constraints
    public class NestedGeneric<T> where T : IBaseInterface
    {
        public T Value { get; set; }
    }

    // Event (for Event and MethodSemantics tables)
    public event EventHandler Event1;

    // Event with custom accessors
    private EventHandler _customEvent;

    public event EventHandler CustomEvent
    {
        add { _customEvent += value; }
        remove { _customEvent -= value; }
    }

    // Method override (for MethodImpl table)
    public override void VirtualMethod()
    {
        // Call to base method (MemberRef)
        base.VirtualMethod();
    }

    // Abstract method implementation (MethodImpl)
    public override void AbstractMethod() { }

    // Method with security attributes (DeclSecurity)
    [SecurityCritical]
    [FileIOPermission(SecurityAction.Demand, Read = @"C:\Test")]
    public void SecureMethod() { }

    // Explicit interface implementation (MethodImpl)
    void IDerivedInterface.Method2<T>(T param) { }

    // Interface implementation (InterfaceImpl and MethodImpl)
    public void Method1() { }

    // Property implementation (PropertyMap, MethodSemantics)
    public int Property1 { get; set; }

    // Generic method (GenericParam)
    public void GenericMethod<T, U>()
        where T : struct
        where U : class, new()
    { }

    // Method with local variables (LocalVarSig)
    public void MethodWithLocals()
    {
        int local1 = 42;
        string local2 = "test";
        var local3 = new List<int>();

        // Try/catch for Exception handling tables
        try
        {
            Console.WriteLine(local1);
            throw new Exception("Test");
        }
        catch (InvalidOperationException ex)
        {
            Console.WriteLine(ex.Message);
        }
        catch (Exception)
        {
            Console.WriteLine("Generic exception");
        }
        finally
        {
            Console.WriteLine("Finally");
        }
    }

    // Async method (generates state machine)
    public async Task<int> AsyncMethod()
    {
        await Task.Delay(100);
        return 42;
    }

    // Method with complex generic return type
    public Dictionary<string, List<KeyValuePair<int, T>>> ComplexGenericMethod<T>()
    {
        return new Dictionary<string, List<KeyValuePair<int, T>>>();
    }

    // Finalizer (special name method)
    ~DerivedClass() { }
}

// Sealed class with extension methods
public static class Extensions
{
    // Extension method (has special flag)
    public static string ToCustomString<T>(this T value)
    {
        return value?.ToString() ?? "null";
    }

    // Extension method with ref return (newer C# feature)
    public static ref int GetReference(this int[] array, int index)
    {
        return ref array[index];
    }
}

// Generic class with multiple type parameters and constraints
public class ComplexGeneric<TKey, TValue, TOutput>
    where TKey : struct, IEquatable<TKey>
    where TValue : class, IDisposable, new()
    where TOutput : IBaseInterface
{
    // Field with generic type
    private Dictionary<TKey, TValue> _dictionary = new Dictionary<TKey, TValue>();

    // Method with constraints on method type parameters
    public void ConstrainedMethod<T, U>(T t, U u)
        where T : TValue
        where U : struct, IConvertible
    { }

    // Generic method that uses containing class type parameters
    public TOutput ProcessValues(TKey key, TValue value)
    {
        return default(TOutput);
    }

    // Nested type that uses containing type's type parameters
    public struct NestedStruct
    {
        public TKey Key;
        public TValue Value;
    }
}

// Class that uses unsafe code
public unsafe class UnsafeClass
{
    // Fixed size buffer (special field type)
    public fixed byte Buffer[128];

    // Method with pointer parameters
    public void PointerMethod(int* ptr)
    {
        // Use pointer
        *ptr = 42;
    }

    // Method with pointer locals
    public void MethodWithPointerLocals()
    {
        int local = 42;
        int* ptr = &local;
        *ptr = 100;
    }
}

// Main program entry point
public class Program
{
    // Special custom attribute for method impl options
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
    public static void Main()
    {
        Console.WriteLine("Hello Metadata World!");

        // Create all the types to ensure they're used
        var derived = new DerivedClass();
        derived.VirtualMethod();
        derived.AsyncMethod().Wait();

        // Variance with arrays and generics
        object[] objArray = new string[10];
        IEnumerable<string> strings = new List<string>();
        IEnumerable<object> objects = strings; // Covariance

        // Use generic types
        var complex = new ComplexGeneric<int, MemoryStream, IBaseInterface>();

        // Use extension methods
        "test".ToCustomString();

        // Local functions (captured variables)
        int outerVar = 42;
        LocalFunction(10);

        void LocalFunction(int param)
        {
            Console.WriteLine(outerVar + param);
        }

        // Switch expression (newer C# feature)
        var value = 1;
        var result = value switch
        {
            1 => "One",
            2 => "Two",
            _ => "Other"
        };

        // LINQ (generates lots of interesting IL)
        var query = Enumerable.Range(1, 10)
            .Where(n => n % 2 == 0)
            .Select(n => n * n)
            .ToList();
    }
}

// Tuple return type (generates ValueTuple type)
public static class TupleExample
{
    public static (int Count, string Name, List<int> Values) GetTuple()
    {
        return (42, "Test", new List<int> { 1, 2, 3 });
    }

    // Deconstruction (special pattern methods)
    public static void Deconstruct(this KeyValuePair<int, string> kvp, out int key, out string value)
    {
        key = kvp.Key;
        value = kvp.Value;
    }
}

// Records (generate special properties and methods)
public record Person(string FirstName, string LastName, int Age);

// Derived record (special inheritance pattern)
public record Employee(string FirstName, string LastName, int Age, string EmployeeId)
    : Person(FirstName, LastName, Age);

// Interface with default implementation (newer C# feature)
public interface IWithDefault
{
    void RequiredMethod();

    // Default implementation
    void DefaultMethod() => Console.WriteLine("Default");
}

// Using ref struct (special type that can only live on stack)
public ref struct RefStruct
{
    public Span<byte> Data;

    public RefStruct(Span<byte> data)
    {
        Data = data;
    }
}
