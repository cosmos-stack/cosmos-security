using Factory = Cosmos.Security.Verification.xxHashFactory;

namespace Cosmos.Security.Verification
{
    /// <summary>
    /// xxHash Hash Function Factory
    /// </summary>
    public static class xxHash
    {
        public static IxxXHash Create(xxHashTypes type = xxHashTypes.xxHashBit32) => Factory.Create(type);
    }
}