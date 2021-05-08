using System;
using System.Threading;
using Cosmos.Security.Cryptography.Core;
using Cosmos.Security.Cryptography.Core.SymmetricAlgorithmImpls;

// ReSharper disable IdentifierTypo
// ReSharper disable InconsistentNaming
// ReSharper disable CheckNamespace

namespace Cosmos.Security.Cryptography
{
    internal class XXTEAFunction : SymmetricCryptoFunction<TeaKey>, ITEA
    {
        private const uint DELTA = 0x9E3779B9;

        public XXTEAFunction(TeaKey key)
        {
            Key = key ?? throw new ArgumentNullException(nameof(key));
        }

        public override TeaKey Key { get; }

        public override int KeySize => Key.Size;

        protected override ICryptoValue EncryptInternal(ArraySegment<byte> originalBytes, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var data = GetBytes(originalBytes);
            var cipher = EncryptCore(ToUInt32Array(data, true), ToUInt32Array(Key.GetKey(), false));
            return CreateCryptoValue(data, ToByteArray(cipher, false), CryptoMode.Encrypt);
        }

        protected override ICryptoValue DecryptInternal(ArraySegment<byte> cipherBytes, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var cipher = GetBytes(cipherBytes);
            var original = DecryptCore(ToUInt32Array(cipher, false), ToUInt32Array(Key.GetKey(), false));
            return CreateCryptoValue(ToByteArray(original, true), cipher, CryptoMode.Decrypt,o=>o.TrimTerminatorWhenDecrypting=true);
        }

        private static uint MX(uint sum, uint y, uint z, int p, uint e, uint[] k)
            => (z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (sum ^ y) + (k[p & 3 ^ e] ^ z);

        private static uint[] EncryptCore(uint[] v, uint[] k)
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

        private static uint[] DecryptCore(uint[] v, uint[] k)
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