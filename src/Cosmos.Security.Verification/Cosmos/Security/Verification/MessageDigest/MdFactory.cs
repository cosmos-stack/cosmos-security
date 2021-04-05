namespace Cosmos.Security.Verification.MessageDigest
{
    /// <summary>
    /// CRC Hash Function Factory
    /// </summary>
    public static class MdFactory
    {
        public static MdFunction Create(MdTypes type = MdTypes.Md5) => new(type);
    }
}