namespace Cosmos.Security.Verification.CRC
{
    /// <summary>
    /// CRC Hash Function Factory
    /// </summary>
    public static class CrcFactory
    {
        public static CrcFunction Create(CrcTypes type = CrcTypes.Crc32) => new(type);
    }
}