namespace Cosmos.Security.Verification.CRC
{
    /// <summary>
    /// CRC Hash Function Factory
    /// </summary>
    public static class CrcFactory
    {
        public static CrcFunction Create(CrcTypes type = CrcTypes.Crc32) => new(type);

        public static CrcFunction Crc32 => Create(CrcTypes.Crc32);

        public static CrcFunction Crc64 => Create(CrcTypes.Crc64);
    }
}