// ReSharper disable once CheckNamespace

namespace Cosmos.Security.Cryptography
{
    public class VigenereFactory
    {
        public static IVigenere Create(string key) => new VigenereFunction(key);
    }
}