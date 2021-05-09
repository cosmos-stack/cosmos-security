namespace Cosmos.Security.Cryptography
{
    public static class RailFenceFactory
    {
        public static IRailFence Create(int key) => new RailFenceFunction(key);
    }
}