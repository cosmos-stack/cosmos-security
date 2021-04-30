using Factory = Cosmos.Security.Verification.AdlerFactory;

// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Verification
{
    /// <summary>
    /// ADLER Hash Function Factory
    /// </summary>
    public static class Adler
    {
        public static IAdler Create(AdlerTypes type = AdlerTypes.Adler32) => Factory.Create(type);
    }

    /// <summary>
    /// ADLER-32 Hash Function Factory
    /// </summary>
    public static class TheAdler32
    {
        public static IAdler Create() => Factory.Adler32;
    }

    /// <summary>
    /// ADLER-64 Hash Function Factory
    /// </summary>
    public static class TheAdler64
    {
        public static IAdler Create() => Factory.Adler64;
    }
}