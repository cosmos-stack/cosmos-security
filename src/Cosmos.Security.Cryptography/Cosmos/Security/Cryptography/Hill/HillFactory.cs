// ReSharper disable once CheckNamespace

namespace Cosmos.Security.Cryptography
{
    public static class HillFactory
    {
        public static IHill Create(int[,] matrix) => new HillFunction(matrix);
    }
}