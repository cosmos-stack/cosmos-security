using System;
// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Verification
{
    internal static class MdTable
    {
        private static (int, uint, uint, bool, bool) Dict(MdTypes type)
        {
            return type switch
            {
                MdTypes.Md2 => (128, 0, 0, false, false),
                MdTypes.Md4 => (128, 0, 0, false, false),
                MdTypes.Md5 => (128, 0, 0, false, false),
                MdTypes.Md5Bit16 => (64, 0, 0, false, false),
                MdTypes.Md5Bit32 => (128, 0, 0, false, false),
                MdTypes.Md5Bit64 => (192, 0, 0, false, false),
                MdTypes.Md6 => (256, 64, 0, false, false),
                MdTypes.Md6Bit128 => (128, 64, 0, false, false),
                MdTypes.Md6Bit256 => (256, 64, 0, false, false),
                MdTypes.Md6Bit512 => (512, 64, 0, false, false),
                MdTypes.Md6Custom => (256, 64, 0, true, true),
                _ => throw new ArgumentOutOfRangeException(nameof(type), type, null)
            };
        }

        public static MdConfig Map(MdTypes type)
        {
            var (hashSize, modeControl, numberOfRound, skipForceConvert, hexTrimLeadingZero) = Dict(type);

            return new MdConfig
            {
                HashSizeInBits = hashSize,
                Type = type,
                ModeControl = modeControl,
                NumberOfRound = numberOfRound,
                SkipForceConvert = skipForceConvert,
                HexTrimLeadingZeroAsDefault = hexTrimLeadingZero,
            };
        }
    }
}