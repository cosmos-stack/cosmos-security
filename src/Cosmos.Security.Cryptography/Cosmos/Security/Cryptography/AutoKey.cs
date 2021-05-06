using Factory = Cosmos.Security.Cryptography.AutoKeyFactory;

namespace Cosmos.Security.Cryptography
{
    public static class AutoKey
    {
        public static IAutoKey Create(string key) => Factory.Create(key);
    }
}