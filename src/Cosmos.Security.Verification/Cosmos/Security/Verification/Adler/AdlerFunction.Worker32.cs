using System;
// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Verification
{
    public partial class AdlerFunction
    {
        private class Adler32Worker : IAdlerWorker
        {
            private readonly uint _mod;
            private readonly uint _nMax;
            private readonly int _hashSizeInBits;

            private uint _checkSum = 1;

            public Adler32Worker(uint mod, uint nMax, int hashSizeInBits)
            {
                _mod = mod;
                _nMax = nMax;
                _hashSizeInBits = hashSizeInBits;
            }

            public byte[] Hash(ReadOnlySpan<byte> buff)
            {
                uint adler = _checkSum & 0xffff;
                uint sum2 = _checkSum >> 16;

                //return BitConverter.GetBytes(HashOptimized(buff, adler, sum2));
                return ToBytes(HashOptimized(buff, adler, sum2), _hashSizeInBits);
            }

            private uint HashOptimized(ReadOnlySpan<byte> buf, uint adler, uint sum2)
            {
                uint n;
                uint len = (uint) buf.Length;
                if (len == 1)
                {
                    adler += buf[0];
                    if (adler >= _mod)
                        adler -= _mod;
                    sum2 += adler;
                    if (sum2 >= _mod)
                        sum2 -= _mod;
                    return adler | (sum2 << 16);
                }

                var idx = 0;
                if (len < 16)
                {
                    while (len-- != 0)
                    {
                        adler += buf[idx++];
                        sum2 += adler;
                    }

                    if (adler >= _mod)
                        adler -= _mod;
                    sum2 = Mod28(sum2, _mod); /* only added so many BASE's */
                    return adler | (sum2 << 16);
                }

                /* do length NMAX blocks -- requires just one modulo operation */

                while (len >= _nMax)
                {
                    len -= _nMax;
                    n = _nMax / 16; /* NMAX is divisible by 16 */
                    do
                    {
                        /* 16 sums unrolled */
                        adler += buf[idx + 0];
                        sum2 += adler;
                        adler += buf[idx + 1];
                        sum2 += adler;
                        adler += buf[idx + 2];
                        sum2 += adler;
                        adler += buf[idx + 3];
                        sum2 += adler;
                        adler += buf[idx + 4];
                        sum2 += adler;
                        adler += buf[idx + 5];
                        sum2 += adler;
                        adler += buf[idx + 6];
                        sum2 += adler;
                        adler += buf[idx + 7];
                        sum2 += adler;
                        adler += buf[idx + 8];
                        sum2 += adler;
                        adler += buf[idx + 9];
                        sum2 += adler;
                        adler += buf[idx + 10];
                        sum2 += adler;
                        adler += buf[idx + 11];
                        sum2 += adler;
                        adler += buf[idx + 12];
                        sum2 += adler;
                        adler += buf[idx + 13];
                        sum2 += adler;
                        adler += buf[idx + 14];
                        sum2 += adler;
                        adler += buf[idx + 15];
                        sum2 += adler;

                        idx += 16;
                    } while (--n != 0);

                    adler = Mod(adler, _mod);
                    sum2 = Mod(sum2, _mod);
                }

                /* do remaining bytes (less than NMAX, still just one modulo) */
                if (len > 0)
                {
                    /* avoid modulos if none remaining */
                    while (len >= 16)
                    {
                        len -= 16;
                        /* 16 sums unrolled */
                        adler += buf[idx + 0];
                        sum2 += adler;
                        adler += buf[idx + 1];
                        sum2 += adler;
                        adler += buf[idx + 2];
                        sum2 += adler;
                        adler += buf[idx + 3];
                        sum2 += adler;
                        adler += buf[idx + 4];
                        sum2 += adler;
                        adler += buf[idx + 5];
                        sum2 += adler;
                        adler += buf[idx + 6];
                        sum2 += adler;
                        adler += buf[idx + 7];
                        sum2 += adler;
                        adler += buf[idx + 8];
                        sum2 += adler;
                        adler += buf[idx + 9];
                        sum2 += adler;
                        adler += buf[idx + 10];
                        sum2 += adler;
                        adler += buf[idx + 11];
                        sum2 += adler;
                        adler += buf[idx + 12];
                        sum2 += adler;
                        adler += buf[idx + 13];
                        sum2 += adler;
                        adler += buf[idx + 14];
                        sum2 += adler;
                        adler += buf[idx + 15];
                        sum2 += adler;
                        idx += 16;
                    }

                    while (len-- != 0)
                    {
                        adler += buf[idx++];
                        sum2 += adler;
                    }

                    adler = Mod(adler, _mod);
                    sum2 = Mod(sum2, _mod);
                }

                /* return recombined sums */
                return adler | (sum2 << 16);
            }

            private static uint Chop(uint a)
            {
                uint tmp = a >> 16;
                a &= 0xffffU;
                a += (tmp << 4) - tmp;
                return a;
            }

            private static uint Mod28(uint a, uint mod)
            {
                a = Chop(a);
                if (a >= mod)
                    a -= mod;
                return a;
            }

            private static uint Mod(uint a, uint mod)
            {
                a = Chop(a);
                a = Mod28(a, mod);
                return a;
            }

            private static byte[] ToBytes(uint value, int bitLength)
            {
                value &= (uint.MaxValue >> (32 - bitLength));


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