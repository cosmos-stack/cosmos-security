using System;
using System.Text;
using Cosmos.Optionals;

// ReSharper disable once CheckNamespace
namespace Cosmos.Encryption
{
    /// <summary>
    /// MurmurHash2 hashing provider
    /// Reference to:
    ///     https://github.com/jitbit/MurmurHash.net/blob/master/MurmurHash.cs
    ///     Author: jitbit.com
    /// </summary>
    public static class MurmurHash2Provider
    {
        // ReSharper disable once InconsistentNaming
        private const uint SEED = 0xc58f1a7a;
        const uint M = 0x5bd1e995;
        const int R = 24;

        /// <summary>
        /// Signature
        /// </summary>
        /// <param name="data">The string you want to hash.</param>
        /// <param name="encoding">The <see cref="T:System.Text.Encoding"/>,default is Encoding.UTF8.</param>
        /// <param name="seed"></param>
        /// <returns></returns>
        public static uint Signature(string data, Encoding encoding = null, uint seed = SEED)
        {
            Checker.Data(data);

            var bytes = encoding.SafeValue().GetBytes(data);

            return Signature(bytes, seed);
        }

        /// <summary>
        /// Signature
        /// </summary>
        /// <param name="data">The data need to hash.</param>
        /// <param name="seed"></param>
        /// <returns></returns>
        public static uint Signature(byte[] data, uint seed = SEED)
        {
            Checker.Buffer(data);
            return SignatureCore(data, seed);
        }

        /// <summary>
        /// Signature hash
        /// </summary>
        /// <param name="data"></param>
        /// <param name="encoding"></param>
        /// <param name="seed"></param>
        /// <returns></returns>
        public static byte[] SignatureHash(string data, Encoding encoding = null, uint seed = SEED)
        {
            return BitConverter.GetBytes(Signature(data, encoding, seed));
        }

        /// <summary>
        /// Signature Hash
        /// </summary>
        /// <param name="data"></param>
        /// <param name="seed"></param>
        /// <returns></returns>
        public static byte[] SignatureHash(byte[] data, uint seed = SEED)
        {
            return BitConverter.GetBytes(Signature(data, seed));
        }

        private static uint SignatureCore(byte[] data, uint seed)
        {
            var length = data.Length;
            if (length == 0)
                return 0;

            var h = seed ^ (uint) length;

            var currentIndex = 0;

            while (length >= 4)
            {
                uint k = (uint) (data[currentIndex++] | data[currentIndex++] << 8 | data[currentIndex++] << 16 | data[currentIndex++] << 24);
                k *= M;
                k ^= k >> R;
                k *= M;

                h *= M;
                h ^= k;
                length -= 4;
            }

            switch (length)
            {
                case 3:
                    h ^= (UInt16) (data[currentIndex++] | data[currentIndex++] << 8);
                    h ^= (uint) (data[currentIndex] << 16);
                    h *= M;
                    break;
                case 2:
                    h ^= (UInt16) (data[currentIndex++] | data[currentIndex] << 8);
                    h *= M;
                    break;
                case 1:
                    h ^= data[currentIndex];
                    h *= M;
                    break;
            }

            h ^= h >> 13;
            h *= M;
            h ^= h >> 15;

            return h;
        }

        /// <summary>
        /// Verify
        /// </summary>
        /// <param name="comparison"></param>
        /// <param name="data"></param>
        /// <param name="encoding"></param>
        /// <param name="seed"></param>
        /// <returns></returns>
        public static bool Verify(long comparison, string data, Encoding encoding = null, uint seed = SEED)
            => comparison == Signature(data, encoding, seed);

        /// <summary>
        /// Verify
        /// </summary>
        /// <param name="comparison"></param>
        /// <param name="data"></param>
        /// <param name="seed"></param>
        /// <returns></returns>
        public static bool Verify(long comparison, byte[] data, uint seed = SEED)
            => comparison == Signature(data, seed);
    }
}