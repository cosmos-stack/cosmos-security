// ReSharper disable once CheckNamespace

namespace Cosmos.Security.Verification
{
    public static class Sm3Factory
    {
        public static ISM3 Create() => new Sm3Function();
    }
}