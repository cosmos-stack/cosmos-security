// ReSharper disable once CheckNamespace

namespace Cosmos.Security.Cryptography
{
    public static class RowTranspositionFactory
    {
        public static IRowTransposition Create(int[] key) => new RowTranspositionFunction(key);
    }
}