using System;

namespace Cosmos.Security.Encryption.Core
{
    /// <summary>
    /// MuemueHash3 core services
    /// Reference to:
    ///     https://github.com/darrenkopp/murmurhash-net/blob/master/MurmurHash/MurmurHash.cs
    ///     Author: Darren Kopp
    ///     Apache License 2.0
    /// </summary>
    internal static partial class MurmurHash3Core
    {
        #region Extensions

        public static uint ToUInt32(this byte[] data, int start)
        {
            return BitConverter.IsLittleEndian
                ? (uint) (data[start] | data[start + 1] << 8 | data[start + 2] << 16 | data[start + 3] << 24)
                : (uint) (data[start] << 24 | data[start + 1] << 16 | data[start + 2] << 8 | data[start + 3]);
        }

        public static ulong ToUInt64(this byte[] data, int start)
        {
            if (BitConverter.IsLittleEndian)
            {
                uint i1 = (uint) (data[start] | data[start + 1] << 8 | data[start + 2] << 16 | data[start + 3] << 24);
                ulong i2 = (ulong) (data[start + 4] | data[start + 5] << 8 | data[start + 6] << 16 | data[start + 7] << 24);
                return (i1 | i2 << 32);
            }
            else
            {
                ulong i1 = (ulong) (data[start] << 24 | data[start + 1] << 16 | data[start + 2] << 8 | data[start + 3] << 24);
                uint i2 = (uint) (data[start + 4] << 24 | data[start + 5] << 16 | data[start + 6] << 8 | data[start + 7]);
                return (i2 | i1 << 32);
            }
        }

        public static uint RotateLeft(this uint x, byte r)
        {
            return (x << r) | (x >> (32 - r));
        }

        public static ulong RotateLeft(this ulong x, byte r)
        {
            return (x << r) | (x >> (64 - r));
        }

        public static uint FMix(this uint h)
        {
            h = (h ^ (h >> 16)) * 0x85ebca6b;
            h = (h ^ (h >> 13)) * 0xc2b2ae35;
            return h ^ (h >> 16);
        }

        public static ulong FMix(this ulong h)
        {
            h = (h ^ (h >> 33)) * 0xff51afd7ed558ccd;
            h = (h ^ (h >> 33)) * 0xc4ceb9fe1a85ec53;
            return h ^ (h >> 33);
        }

        #endregion
    }
}