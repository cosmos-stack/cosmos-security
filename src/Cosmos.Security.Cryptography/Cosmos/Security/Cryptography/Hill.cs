using Factory = Cosmos.Security.Cryptography.HillFactory;

namespace Cosmos.Security.Cryptography
{
    public static class Hill
    {
        public static IHill Create(int[,] matrix) => Factory.Create(matrix);
    }
}