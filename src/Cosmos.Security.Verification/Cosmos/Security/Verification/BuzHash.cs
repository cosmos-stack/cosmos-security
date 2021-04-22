using Factory = Cosmos.Security.Verification.BuzHashFactory;

namespace Cosmos.Security.Verification
{
    public static class BuzHash
    {
        public static BuzHashFunction Create(BuzHashTypes type = BuzHashTypes.BuzHashBit64) => Factory.Create(type);

        public static BuzHashFunction Create(BuzHashTypes type, BuzHashConfig config) => Factory.Create(type, config);
    }
}