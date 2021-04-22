using Cosmos.Security.Verification.Core;
using Factory = Cosmos.Security.Verification.FarmHashFactory;

namespace Cosmos.Security.Verification
{
    public static class FarmHash
    {
        public static HashFunctionBase Create(FarmHashTypes type = FarmHashTypes.Fingerprint64) => Factory.Create(type);
    }
}