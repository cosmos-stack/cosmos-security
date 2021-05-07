using Factory = Cosmos.Security.Verification.MetroHashFactory;

namespace Cosmos.Security.Verification
{
    public static class MetroHash
    {
        public static IMetroHash Create(MetroHashTypes type = MetroHashTypes.MetroHashBit64) => Factory.Create(type);

        public static IMetroHash Create(MetroHashTypes type, MetroHashConfig config) => Factory.Create(type, config);
    }
}