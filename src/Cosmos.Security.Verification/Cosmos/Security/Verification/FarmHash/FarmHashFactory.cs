using Cosmos.Security.Verification.Core;

// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Verification
{
    public static class FarmHashFactory
    {
        public static HashFunctionBase Create(FarmHashTypes type = FarmHashTypes.Fingerprint64)
        {
            return type switch
            {
                FarmHashTypes.Fingerprint32 => new FarmHashFingerprint032Function(),
                FarmHashTypes.Fingerprint64 => new FarmHashFingerprint064Function(),
                FarmHashTypes.Fingerprint128 => new FarmHashFingerprint128Function(),
                _ => new FarmHashFingerprint064Function()
            };
        }
    }
}