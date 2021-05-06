using Factory = Cosmos.Security.Verification.FnvFactory;

// ReSharper disable InconsistentNaming

namespace Cosmos.Security.Verification
{
    public static class FNV
    {
        public static IFNV Create(FnvTypes type = FnvTypes.Fnv1aBit64) => Factory.Create(type);

        public static IFNV Create(FnvTypes type, FnvConfig config) => Factory.Create(type, config);
    }
}