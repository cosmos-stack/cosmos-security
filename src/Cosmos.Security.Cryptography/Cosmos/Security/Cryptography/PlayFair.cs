using Factory = Cosmos.Security.Cryptography.PlayFairFactory;

namespace Cosmos.Security.Cryptography
{
    public static class PlayFair
    {
        public static IPlayFair Create(string key) => Factory.Create(key);
    }
}