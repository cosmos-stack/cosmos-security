// ReSharper disable once CheckNamespace

namespace Cosmos.Security.Cryptography
{
    public static class MonoalphabeticFactory
    {
        public static IMonoalphabetic Create() => new MonoalphabeticFunction();
    }
}