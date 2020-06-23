/*
 * A copy of https://github.com/linnaea/Cryptography.GM
 *     Author: Linnaea Von Lavia
 *     Site: http://linnaea.moe/
 */

using System;
using System.Numerics;

// ReSharper disable InconsistentNaming
// ReSharper disable once CheckNamespace

namespace Cryptography.GM.ECMath
{
    internal static class NAF
    {
        public static byte[] ToNAFBytes(this BigInteger x)
        {
            var xb = x.ToByteArray();
            var naf = new byte[xb.Length * 4 + 1];
            var i = 0;
            while (!x.IsZero)
            {
                var k = 0;
                if (!x.IsEven)
                {
                    k = (int) (2 - x % 4);
                }

                var nibble = (byte) (k & 0xF);
                nibble <<= (i & 1) << 2;
                naf[i / 2] |= nibble;
                x = (x - k) / 2;
                i++;
            }

            Array.Resize(ref naf, (i + 1) / 2);
            return naf;
        }

        public static sbyte H(this byte b) => (sbyte) ((sbyte) b >> 4);
        public static sbyte L(this byte b) => (sbyte) ((sbyte) (b << 4) >> 4);
        public static sbyte NafValue(this byte v) => (sbyte) (v.H() * 2 + v.L());
    }
}