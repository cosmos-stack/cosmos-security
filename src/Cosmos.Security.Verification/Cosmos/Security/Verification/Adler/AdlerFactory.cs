namespace Cosmos.Security.Verification.Adler
{
    /// <summary>
    /// ADLER Hash Function Factory
    /// </summary>
    public static class AdlerFactory
    {
        public static AdlerFunction Create(AdlerTypes type = AdlerTypes.Adler32) => new(type);

        public static AdlerFunction Adler32 => Create(AdlerTypes.Adler32);

        public static AdlerFunction Adler64 => Create(AdlerTypes.Adler64);
    }
}