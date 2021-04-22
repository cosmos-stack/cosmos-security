using Cosmos.Security.Verification.Core;
using Factory = Cosmos.Security.Verification.FnvFactory;

namespace Cosmos.Security.Verification
{
    public static class FNV
    {
        public static StreamableHashFunctionBase Create(FnvTypes type = FnvTypes.Fnv1aBit64) => Factory.Create(type);

        public static StreamableHashFunctionBase Create(FnvTypes type, FnvConfig config) => Factory.Create(type, config);
    }

}