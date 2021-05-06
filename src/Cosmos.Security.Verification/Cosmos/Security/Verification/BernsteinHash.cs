using Factory = Cosmos.Security.Verification.BernsteinHashFactory;

namespace Cosmos.Security.Verification
{
    public static class BernsteinHash
    {
        public static IBernsteinHash Create(BernsteinHashTypes type = BernsteinHashTypes.Time33) => Factory.Create(type);
    }

    public static class Time33
    {
        public static IBernsteinHash Create() => new Time33Function();
    }
}