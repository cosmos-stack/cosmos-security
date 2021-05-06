// ReSharper disable once CheckNamespace

namespace Cosmos.Security.Cryptography
{
    public static class AutoKeyFactory
    {
        public static IAutoKey Create(string key) => new AutoKeyFunction(key);
    }
}