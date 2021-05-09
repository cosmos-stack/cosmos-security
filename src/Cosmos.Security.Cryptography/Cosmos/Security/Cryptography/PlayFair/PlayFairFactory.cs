// ReSharper disable once CheckNamespace

namespace Cosmos.Security.Cryptography
{
    public static class PlayFairFactory
    {
        public static IPlayFair Create(string key) => new PlayFairFunction(key);
    }
}