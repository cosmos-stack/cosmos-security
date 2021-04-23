using Cosmos.Security.Verification.Core;
using Factory = Cosmos.Security.Verification.MetroHashFactory;

namespace Cosmos.Security.Verification
{
    public static class MetroHash
    {
        public static StreamableHashFunctionBase Create(MetroHashTypes type = MetroHashTypes.MetroHashBit64) => Factory.Create(type);

        public static StreamableHashFunctionBase Create(MetroHashTypes type, MetroHashConfig config) => Factory.Create(type, config);
    }
}