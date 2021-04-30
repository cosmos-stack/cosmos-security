using System;
// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Verification
{
    internal partial class AdlerFunction
    {
        private class Adler64Worker : IAdlerWorker
        {
            private readonly ulong _mod;
            private readonly uint _nMax;
            private readonly int _maxPart;
            private readonly int _hashSizeInBits;

            private ulong _checkSum = 1;

            public Adler64Worker(ulong mod, uint nMax, int maxPart, int hashSizeInBits)
            {
                _mod = mod;
                _nMax = nMax;
                _maxPart = maxPart;
                _hashSizeInBits = hashSizeInBits;
            }

            public byte[] Hash(ReadOnlySpan<byte> buff)
            {
                ulong adler = _checkSum & 0xffffffff;
                ulong sum2 = _checkSum >> 32;

                if (buff.Length > _maxPart)
                {
                    int parts = (buff.Length / _maxPart) + 1;
                    ulong result = 0;
                    for (int i = 0; i < parts; i++)
                    {
                        var start = _maxPart * i;
                        var count = Math.Min(buff.Length - start, _maxPart);
                        var slice = buff.Slice(start, count);
                        result = HashOptimized(slice, adler, sum2);
                        adler = result & 0xffffffff;
                        sum2 = result >> 32;
                    }

                    return ToBytes(result, _hashSizeInBits);
                }

                return ToBytes(HashOptimized(buff, adler, sum2), _hashSizeInBits);
            }

            private ulong HashOptimized(ReadOnlySpan<byte> buff, ulong adler, ulong sum2)
            {
                ulong n;
                ulong len = (ulong) buff.Length;
                if (len == 1)
                {
                    adler += buff[0];
                    if (adler >= _mod)
                        adler -= _mod;
                    sum2 += adler;
                    if (sum2 >= _mod)
                        sum2 -= _mod;
                    return adler | (sum2 << 32);
                }

                var idx = 0;
                if (len < 16)
                {
                    while (len-- != 0)
                    {
                        adler += buff[idx++];
                        sum2 += adler;
                    }

                    if (adler >= _mod)
                        adler -= _mod;
                    sum2 %= _mod; /* only added so many BASE's */
                    return adler | (sum2 << 32);
                }

                /* do length NMAX blocks -- requires just one modulo operation */

                while (len >= _nMax)
                {
                    len -= _nMax;
                    n = _nMax / 16; /* NMAX is divisible by 16 */
                    do
                    {
                        /* 16 sums unrolled */
                        adler += buff[idx + 0];
                        sum2 += adler;
                        adler += buff[idx + 1];
                        sum2 += adler;
                        adler += buff[idx + 2];
                        sum2 += adler;
                        adler += buff[idx + 3];
                        sum2 += adler;
                        adler += buff[idx + 4];
                        sum2 += adler;
                        adler += buff[idx + 5];
                        sum2 += adler;
                        adler += buff[idx + 6];
                        sum2 += adler;
                        adler += buff[idx + 7];
                        sum2 += adler;
                        adler += buff[idx + 8];
                        sum2 += adler;
                        adler += buff[idx + 9];
                        sum2 += adler;
                        adler += buff[idx + 10];
                        sum2 += adler;
                        adler += buff[idx + 11];
                        sum2 += adler;
                        adler += buff[idx + 12];
                        sum2 += adler;
                        adler += buff[idx + 13];
                        sum2 += adler;
                        adler += buff[idx + 14];
                        sum2 += adler;
                        adler += buff[idx + 15];
                        sum2 += adler;

                        idx += 16;
                    } while (--n != 0);

                    adler %= _mod;
                    sum2 %= _mod;
                }

                /* do remaining bytes (less than NMAX, still just one modulo) */
                if (len > 0)
                {
                    /* avoid modulos if none remaining */
                    while (len >= 16)
                    {
                        len -= 16;
                        /* 16 sums unrolled */
                        adler += buff[idx + 0];
                        sum2 += adler;
                        adler += buff[idx + 1];
                        sum2 += adler;
                        adler += buff[idx + 2];
                        sum2 += adler;
                        adler += buff[idx + 3];
                        sum2 += adler;
                        adler += buff[idx + 4];
                        sum2 += adler;
                        adler += buff[idx + 5];
                        sum2 += adler;
                        adler += buff[idx + 6];
                        sum2 += adler;
                        adler += buff[idx + 7];
                        sum2 += adler;
                        adler += buff[idx + 8];
                        sum2 += adler;
                        adler += buff[idx + 9];
                        sum2 += adler;
                        adler += buff[idx + 10];
                        sum2 += adler;
                        adler += buff[idx + 11];
                        sum2 += adler;
                        adler += buff[idx + 12];
                        sum2 += adler;
                        adler += buff[idx + 13];
                        sum2 += adler;
                        adler += buff[idx + 14];
                        sum2 += adler;
                        adler += buff[idx + 15];
                        sum2 += adler;
                        idx += 16;
                    }

                    while (len-- != 0)
                    {
                        adler += buff[idx++];
                        sum2 += adler;
                    }

                    adler %= _mod;
                    sum2 %= _mod;
                }

                /* return recombined sums */
                return adler | (sum2 << 32);
            }

            private static byte[] ToBytes(ulong value, int bitLength)
            {
                value &= (ulong.MaxValue >> (64 - bitLength));


                var valueBytes = new byte[(bitLength + 7) / 8];

                for (var x = 0; x < valueBytes.Length; ++x)
                {
                    valueBytes[x] = (byte) value;
                    value >>= 8;
                }

                return valueBytes;
            }
        }
    }
}