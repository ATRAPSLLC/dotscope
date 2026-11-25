' A method with locals, constants and scopes, under file-level imports of every kind Visual Basic
' writes: a namespace, a type, an alias and an XML namespace.
Imports System.Collections.Generic
Imports Strings = System.String
Imports <xmlns:probe="http://example.invalid/probe">

Module Program
    Function Main(args As String()) As Integer
        Const greeting As String = "hello"
        Const count As Integer = 3
        Dim values As New List(Of Integer)
        For index As Integer = 0 To count - 1
            Dim doubled As Integer = index * 2
            values.Add(doubled)
        Next
        Dim builder As New StringBuilder(greeting)
        Dim element = <probe:item><%= values.Count %></probe:item>
        Console.WriteLine(Strings.Concat(builder.ToString(), element.Value))
        Return 0
    End Function
End Module
