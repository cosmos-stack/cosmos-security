using Factory = Cosmos.Security.Cryptography.RowTranspositionFactory;

namespace Cosmos.Security.Cryptography
{
    public static class RowTransposition
    {
        public static IRowTransposition Create(int[] key) => Factory.Create(key);
    }
}