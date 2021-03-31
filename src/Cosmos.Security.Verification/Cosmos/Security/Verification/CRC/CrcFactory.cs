namespace Cosmos.Security.Verification.CRC
{
    public static class CrcFactory
    {
        public static CrcFunction Create(CrcTypes type = CrcTypes.Crc32) => new(type);
    }
}