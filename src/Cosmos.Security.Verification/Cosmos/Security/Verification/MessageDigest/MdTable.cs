using System;

namespace Cosmos.Security.Verification.MessageDigest
{
    public static class MdTable
    {
        public static MdConfig Map(MdTypes type)
        {
            var hashSize = type switch
            {
                MdTypes.Md2 => 128,
                MdTypes.Md4 => 128,
                MdTypes.Md5 => 128,
                MdTypes.Md5Bit16 => 64,
                MdTypes.Md5Bit32 => 128,
                MdTypes.Md5Bit64 => 192,
                _ => throw new ArgumentOutOfRangeException(nameof(type), type, null)
            };

            return new MdConfig
            {
                HashSizeInBits = hashSize,
                Type = type
            };
        }
    }
}