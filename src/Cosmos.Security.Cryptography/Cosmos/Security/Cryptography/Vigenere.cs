using Factory = Cosmos.Security.Cryptography.VigenereFactory;

namespace Cosmos.Security.Cryptography
{
    public static class Vigenere
    {
        public static IVigenere Create(string key) => Factory.Create(key);
    }
}