using Factory = Cosmos.Security.Cryptography.MonoalphabeticFactory;

namespace Cosmos.Security.Cryptography
{
    public static class Monoalphabetic
    {
        public static IMonoalphabetic Create() => Factory.Create();
    }
}