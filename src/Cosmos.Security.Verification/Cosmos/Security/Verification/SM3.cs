using Factory = Cosmos.Security.Verification.Sm3Factory;

// ReSharper disable InconsistentNaming

namespace Cosmos.Security.Verification
{
    public static class SM3
    {
        public static ISM3 Create() => Factory.Create();
    }
}