using System;
// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Verification
{
    internal static class CrcTable
    {
        private static (int, ulong, ulong, bool, bool, ulong) Dict(CrcTypes type)
        {
            return type switch
            {
                //CRC-3
                CrcTypes.Crc3Rohc => (3, 0x3, 0x7, true, true, 0x0),

                //CRC-4
                CrcTypes.Crc4Itu => (4, 0x3, 0x0, true, true, 0x0),

                //CRC-5
                CrcTypes.Crc5Epc => (5, 0x09, 0x09, false, false, 0x00),
                CrcTypes.Crc5Itu => (5, 0x15, 0x00, true, true, 0x00),
                CrcTypes.Crc5Usb => (5, 0x05, 0x1f, true, true, 0x1f),

                //CRC-6
                CrcTypes.Crc6Cdma2000A => (6, 0x27, 0x3f, false, false, 0x00),
                CrcTypes.Crc6Cdma2000B => (6, 0x07, 0x3f, false, false, 0x00),
                CrcTypes.Crc6Darc => (6, 0x19, 0x00, true, true, 0x00),
                CrcTypes.Crc6Itu => (6, 0x03, 0x00, true, true, 0x00),

                //CRC-7
                CrcTypes.Crc7 => (7, 0x09, 0x00, false, false, 0x00),
                CrcTypes.Crc7Rohc => (7, 0x4f, 0x7f, true, true, 0x00),
                CrcTypes.Crc7Mmc => (7, 0x09, 0x00, false, false, 0x00),

                //CRC-8
                CrcTypes.Crc8 => (8, 0x7, 0x0, false, false, 0x00),
                CrcTypes.Crc8Cdma2000 => (8, 0x9b, 0xff, false, false, 0x00),
                CrcTypes.Crc8Darc => (8, 0x39, 0x00, true, true, 0x00),
                CrcTypes.Crc8DvbS2 => (8, 0xd5, 0x00, false, false, 0x00),
                CrcTypes.Crc8Ebu => (8, 0x1d, 0xff, true, true, 0x00),
                CrcTypes.Crc8ICode => (8, 0x1d, 0xfd, false, false, 0x00),
                CrcTypes.Crc8Itu => (8, 0x07, 0x00, false, false, 0x55),
                CrcTypes.Crc8Maxim => (8, 0x31, 0x00, true, true, 0x00),
                CrcTypes.Crc8Rohc => (8, 0x7, 0xff, true, true, 0x00),
                CrcTypes.Crc8Wcdma => (8, 0x9b, 0x00, true, true, 0x00),

                //CRC-10
                CrcTypes.Crc10 => (10, 0x233, 0x000, false, false, 0x000),
                CrcTypes.Crc10Cdma2000 => (10, 0x3d9, 0x3ff, false, false, 0x000),

                //CRC-11
                CrcTypes.Crc11 => (11, 0x385, 0x1A, false, false, 0x0),

                //CRC-12
                CrcTypes.Crc123Gpp => (12, 0x80F, 0x0, false, true, 0x0),
                CrcTypes.Crc12Cdma2000 => (12, 0xF13, 0xFFF, false, false, 0x0),
                CrcTypes.Crc12Dect => (12, 0x80F, 0x0, false, false, 0x0),

                //CRC-13
                CrcTypes.Crc13Bbc => (13, 0x1CF5, 0x0, false, false, 0x0),

                //CRC-14
                CrcTypes.Crc14Darc => (14, 0x805, 0x0, true, true, 0x0),

                //CRC-15
                CrcTypes.Crc15 => (15, 0x4599, 0x0, false, false, 0x0),
                CrcTypes.Crc15Mpt1327 => (15, 0x6815, 0x0, false, false, 0x1),

                //CRC-16
                CrcTypes.Crc16Ccitt => (16, 0x1021, 0x0, true, true, 0x0),
                CrcTypes.Crc16CcittFalse => (16, 0x1021, 0xFFFF, false, false, 0x0),
                CrcTypes.Crc16Arc => (16, 0x8005, 0x0, true, true, 0x0),
                CrcTypes.Crc16AugCcitt => (16, 0x1021, 0x1D0F, false, false, 0x0),
                CrcTypes.Crc16Buypass => (16, 0x8005, 0x0, false, false, 0x0),
                CrcTypes.Crc16Cdma2000 => (16, 0xC867, 0xFFFF, false, false, 0x0),
                CrcTypes.Crc16Dds110 => (16, 0x8005, 0x800D, false, false, 0x0),
                CrcTypes.Crc16DectR => (16, 0x589, 0x0, false, false, 0x1),
                CrcTypes.Crc16DectX => (16, 0x589, 0x0, false, false, 0x0),
                CrcTypes.Crc16Dnp => (16, 0x3D65, 0x0, true, true, 0xFFFF),
                CrcTypes.Crc16En13757 => (16, 0x3D65, 0x0, false, false, 0xFFFF),
                CrcTypes.Crc16Genibus => (16, 0x1021, 0xFFFF, false, false, 0xFFFF),
                CrcTypes.Crc16Maxim => (16, 0x8005, 0x0, true, true, 0xFFFF),
                CrcTypes.Crc16Mcrf4Xx => (16, 0x1021, 0xFFFF, true, true, 0x0),
                CrcTypes.Crc16Riello => (16, 0x1021, 0xB2AA, true, true, 0x0),
                CrcTypes.Crc16T10Dif => (16, 0x8BB7, 0x0, false, false, 0x0),
                CrcTypes.Crc16Teledisk => (16, 0xA097, 0x0, false, false, 0x0),
                CrcTypes.Crc16Tms37157 => (16, 0x1021, 0x89EC, true, true, 0x0),
                CrcTypes.Crc16Usb => (16, 0x8005, 0xFFFF, true, true, 0xFFFF),
                CrcTypes.CrcA => (16, 0x1021, 0xC6C6, true, true, 0x0),
                CrcTypes.Crc16Kermit => (16, 0x1021, 0x0, true, true, 0x0),
                CrcTypes.Crc16Modbus => (16, 0x8005, 0xFFFF, true, true, 0x0),
                CrcTypes.Crc16X25 => (16, 0x1021, 0xFFFF, true, true, 0xFFFF),
                CrcTypes.Crc16Xmodem => (16, 0x1021, 0x0, false, false, 0x0),
                CrcTypes.Crc16Ibm => (16, 0x8005, 0x0, true, true, 0x0),

                //CRC-24
                CrcTypes.Crc24 => (24, 0x864CFB, 0xB704CE, false, false, 0x0),
                CrcTypes.Crc24FlexrayA => (24, 0x5D6DCB, 0xFEDCBA, false, false, 0x0),
                CrcTypes.Crc24FlexrayB => (24, 0x5D6DCB, 0xABCDEF, false, false, 0x0),

                //CRC-31
                CrcTypes.Crc31Philips => (31, 0x4C11DB7, 0x7FFFFFFF, false, false, 0x7FFFFFFF),

                //CRC-32
                CrcTypes.Crc32 => (32, 0x04C11DB7, 0xFFFFFFFF, true, true, 0xFFFFFFFF),
                CrcTypes.Crc32Bzip2 => (32, 0x04C11DB7, 0xFFFFFFFF, false, false, 0xFFFFFFFF),
                CrcTypes.Crc32C => (32, 0x1EDC6F41, 0xFFFFFFFF, true, true, 0xFFFFFFFF),
                CrcTypes.Crc32D => (32, 0xA833982B, 0xFFFFFFFF, true, true, 0xFFFFFFFF),
                CrcTypes.Crc32Jamcrc => (32, 0x04C11DB7, 0xFFFFFFFF, true, true, 0x00000000),
                CrcTypes.Crc32Mpeg2 => (32, 0x04C11DB7, 0xFFFFFFFF, false, false, 0x00000000),
                CrcTypes.Crc32Posix => (32, 0x04C11DB7, 0x00000000, false, false, 0xFFFFFFFF),
                CrcTypes.Crc32Q => (32, 0x814141AB, 0x00000000, false, false, 0x00000000),
                CrcTypes.Crc32Xfer => (32, 0x000000AF, 0x00000000, false, false, 0x00000000),

                //CRC-40
                CrcTypes.Crc40Gsm => (40, 0x4820009, 0x0, false, false, 0xFFFFFFFFFF),

                //CRC-64
                CrcTypes.Crc64 => (64, 0x42F0E1EBA9EA3693, 0x00000000, false, false, 0x00000000),
                CrcTypes.Crc64We => (64, 0x42F0E1EBA9EA3693, 0xFFFFFFFFFFFFFFFF, false, false, 0xFFFFFFFFFFFFFFFF),
                CrcTypes.Crc64Xz => (64, 0x42F0E1EBA9EA3693, 0xFFFFFFFFFFFFFFFF, true, true, 0xFFFFFFFFFFFFFFFF),

                //default
                _ => throw new ArgumentOutOfRangeException(nameof(type), type, null)
            };
        }

        public static CrcConfig Map(CrcTypes type)
        {
            (int hashSize, ulong poly, ulong init, bool refIn, bool refOut, ulong xorOut) = Dict(type);

            return new CrcConfig
            {
                HashSizeInBits = hashSize,
                Polynomial = poly,
                InitialValue = init,
                ReflectIn = refIn,
                ReflectOut = refOut,
                XOrOut = xorOut
            };
        }
    }
}