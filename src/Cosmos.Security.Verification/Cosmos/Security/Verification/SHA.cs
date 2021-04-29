using Factory = Cosmos.Security.Verification.ShaFactory;

// ReSharper disable InconsistentNaming

namespace Cosmos.Security.Verification
{
    /// <summary>
    /// SHA Hash Function Factory
    /// </summary>
    public static class SHA
    {
        public static ISHA Create(ShaTypes type = ShaTypes.Sha1) => Factory.Create(type);
    }

    /// <summary>
    /// SHA1 Hash Function Factory
    /// </summary>
    public static class SHA1
    {
        public static ISHA Create() => Factory.Create(ShaTypes.Sha1);
    }

    /// <summary>
    /// SHA2/256 Hash Function Factory
    /// </summary>
    public static class SHA256
    {
        public static ISHA Create() => Factory.Create(ShaTypes.Sha256);
    }

    /// <summary>
    /// SHA2/512 Hash Function Factory
    /// </summary>
    public static class SHA512
    {
        public static ISHA Create() => Factory.Create(ShaTypes.Sha512);
    }
}