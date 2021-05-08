// ReSharper disable once CheckNamespace

namespace Cosmos.Security.Cryptography
{
    public static class CeaserFactory
    {
        public static ICeaser Create(int key) => new CeaserFunction(key);
    }
}