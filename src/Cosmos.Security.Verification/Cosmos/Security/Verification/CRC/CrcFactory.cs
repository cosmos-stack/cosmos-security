// ReSharper disable once CheckNamespace

namespace Cosmos.Security.Verification
{
    /// <summary>
    /// CRC Hash Function Factory
    /// </summary>
    public static class CrcFactory
    {
        public static ICRC Create(CrcTypes type = CrcTypes.Crc32) => new CrcFunction(type);

        public static ICRC Crc32 => Create(CrcTypes.Crc32);

        public static ICRC Crc64 => Create(CrcTypes.Crc64);
    }
}