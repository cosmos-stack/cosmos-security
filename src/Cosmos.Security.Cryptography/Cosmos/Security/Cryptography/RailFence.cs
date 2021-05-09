using Factory = Cosmos.Security.Cryptography.RailFenceFactory;

namespace Cosmos.Security.Cryptography
{
    public static class RailFence
    {
        public static IRailFence Create(int key) => Factory.Create(key);
    }
}