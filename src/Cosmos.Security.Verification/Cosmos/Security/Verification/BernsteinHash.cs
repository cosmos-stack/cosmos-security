using Cosmos.Security.Verification.Core;
using Factory = Cosmos.Security.Verification.BernsteinHashFactory;

namespace Cosmos.Security.Verification
{
    public static class BernsteinHash
    {
        public static StreamableHashFunctionBase Create(BernsteinHashTypes type = BernsteinHashTypes.Time33) => Factory.Create(type);
    }

    public static class Time33
    {
        public static Time33Function Create() => new();
    }
}