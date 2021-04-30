using Factory = Cosmos.Security.Verification.AdlerFactory;

// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Verification
{
    /// <summary>
    /// ADLER Hash Function Factory
    /// </summary>
    public static class AdlerFactory
    {
        public static IAdler Create(AdlerTypes type = AdlerTypes.Adler32) => new AdlerFunction(type);

        public static IAdler Adler32 => Create(AdlerTypes.Adler32);

        public static IAdler Adler64 => Create(AdlerTypes.Adler64);
    }
}