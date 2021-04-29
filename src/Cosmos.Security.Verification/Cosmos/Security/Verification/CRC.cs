using Factory = Cosmos.Security.Verification.CrcFactory;

// ReSharper disable InconsistentNaming

namespace Cosmos.Security.Verification
{
    /// <summary>
    /// CRC Hash Function Factory
    /// </summary>
    public static class CRC
    {
        public static ICRC Create(CrcTypes type = CrcTypes.Crc32) => Factory.Create(type);
    }

    /// <summary>
    /// CRC32 Hash Function Factory
    /// </summary>
    public static class CRC32
    {
        public static ICRC Create() => Factory.Crc32;
    }

    /// <summary>
    /// CRC64 Hash Function Factory
    /// </summary>
    public static class CRC64
    {
        public static ICRC Create() => Factory.Crc64;
    }
}