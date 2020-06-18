using System;
using System.Text;
using Cosmos.Encryption.Abstractions;
using Cosmos.Optionals;

/*
 * Reference to:
 *      XXTEA/XXTEA-dotnet
 *      URL:    https://github.com/xxtea/xxtea-dotnet
 *      Author: Ma Bingyao
 *      Email:  mabingyao@gmail.com
 *
 *      Encryption Algorithm
 *      Author:
 *          David J. Wheeler
 *          Roger M. Needham
 */

namespace Cosmos.Encryption.Symmetric
{
    /// <summary>
    /// XXTEA encryption provider
    /// </summary>
    // ReSharper disable once IdentifierTypo
    // ReSharper disable once InconsistentNaming
    public sealed class XXTEAEncryptionProvider : ISymmetricEncryption
    {
        // ReSharper disable once InconsistentNaming
        private const uint DELTA = 0x9E3779B9;

        private XXTEAEncryptionProvider() { }

        // ReSharper disable once InconsistentNaming
        private static uint MX(uint sum, uint y, uint z, int p, uint e, uint[] k)
            => (z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (sum ^ y) + (k[p & 3 ^ e] ^ z);

        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public static string Encrypt(string data, string key, Encoding encoding = null)
        {
            if (string.IsNullOrWhiteSpace(data))
                return data;

            encoding = encoding.SafeValue();
            return Convert.ToBase64String(Encrypt(encoding.GetBytes(data), encoding.GetBytes(key)));
        }

        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public static string Encrypt(byte[] data, string key, Encoding encoding = null)
        {
            return Convert.ToBase64String(data.Length == 0
                ? data
                : Encrypt(data, encoding.SafeValue().GetBytes(key)));
        }

        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static byte[] Encrypt(byte[] data, byte[] key)
        {
            return data.Length == 0
                ? data
                : ToByteArray(Encrypt(ToUInt32Array(data, true), ToUInt32Array(FixKey(key), false)), false);
        }

        /// <summary>
        /// Decrypt
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public static string Decrypt(string data, string key, Encoding encoding = null)
        {
            if (string.IsNullOrWhiteSpace(data))
                return data;

            encoding = encoding.SafeValue();
            return encoding.GetString(Decrypt(Convert.FromBase64String(data), encoding.GetBytes(key)));
        }

        /// <summary>
        /// Decrypt
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public static string Decrypt(byte[] data, string key, Encoding encoding = null)
        {
            encoding = encoding.SafeValue();
            return encoding.GetString(Decrypt(data, encoding.GetBytes(key)));
        }

        /// <summary>
        /// Decrypt
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static byte[] Decrypt(byte[] data, byte[] key)
        {
            return data.Length == 0
                ? data
                : ToByteArray(Decrypt(ToUInt32Array(data, false), ToUInt32Array(FixKey(key), false)), true);
        }

        private static uint[] Encrypt(uint[] v, uint[] k)
        {
            var n = v.Length - 1;
            if (n < 1) return v;
            uint z = v[n], y, sum = 0, e;
            int p, q = 6 + 52 / (n + 1);
            unchecked
            {
                while (0 < q--)
                {
                    sum += DELTA;
                    e = sum >> 2 & 3;
                    for (p = 0; p < n; p++)
                    {
                        y = v[p + 1];
                        z = v[p] += MX(sum, y, z, p, e, k);
                    }

                    y = v[0];
                    z = v[n] += MX(sum, y, z, p, e, k);
                }
            }

            return v;
        }

        private static uint[] Decrypt(uint[] v, uint[] k)
        {
            var n = v.Length - 1;
            if (n < 1) return v;
            uint z, y = v[0], sum, e;
            int p, q = 6 + 52 / (n + 1);
            unchecked
            {
                sum = (uint) (q * DELTA);
                while (sum != 0)
                {
                    e = sum >> 2 & 3;
                    for (p = n; p > 0; p--)
                    {
                        z = v[p - 1];
                        y = v[p] -= MX(sum, y, z, p, e, k);
                    }

                    z = v[n];
                    y = v[0] -= MX(sum, y, z, p, e, k);
                    sum -= DELTA;
                }
            }

            return v;
        }

        private static byte[] FixKey(byte[] key)
        {
            if (key.Length == 16) return key;
            byte[] fixedKey = new byte[16];
            if (key.Length < 16)
            {
                key.CopyTo(fixedKey, 0);
            }
            else
            {
                Array.Copy(key, 0, fixedKey, 0, 16);
            }

            return fixedKey;
        }

        private static uint[] ToUInt32Array(byte[] data, bool includeLength)
        {
            var length = data.Length;
            var n = (((length & 3) == 0) ? (length >> 2) : ((length >> 2) + 1));
            uint[] ret;
            if (includeLength)
            {
                ret = new uint[n + 1];
                ret[n] = (uint) length;
            }
            else
            {
                ret = new uint[n];
            }

            for (var i = 0; i < length; i++)
            {
                ret[i >> 2] |= (uint) data[i] << ((i & 3) << 3);
            }

            return ret;
        }

        private static byte[] ToByteArray(uint[] data, bool includeLength)
        {
            var n = data.Length << 2;
            if (includeLength)
            {
                var m = (int) data[data.Length - 1];
                n -= 4;
                if ((m < n - 3) || (m > n))
                    return null;
                n = m;
            }

            var ret = new byte[n];
            for (var i = 0; i < n; i++)
                ret[i] = (byte) (data[i >> 2] >> ((i & 3) << 3));
            return ret;
        }
    }
}