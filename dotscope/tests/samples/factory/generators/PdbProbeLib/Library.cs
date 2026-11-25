namespace ProbeLib.Shapes
{
    public sealed class Square
    {
        public Square(int side) => Side = side;

        public int Side { get; }

        public int Area() => Side * Side;
    }
}
