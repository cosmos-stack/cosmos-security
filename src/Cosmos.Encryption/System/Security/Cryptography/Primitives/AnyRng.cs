/*
 * A copy of https://github.com/linnaea/Cryptography.GM
 *     Author: Linnaea Von Lavia
 *     Site: http://linnaea.moe/
 */

using System.Numerics;
using Cryptography.GM;

namespace System.Security.Cryptography.Primitives
{
    internal abstract class AnyRng
    {
        public abstract void NextBytes(byte[] buf);

        public BigInteger NextBigInt(BigInteger minInclusive, BigInteger maxExclusive)
        {
            var range = maxExclusive - minInclusive;
            var rb = range.ToByteArray();
            BigInteger r;
            byte lastMask = 0;
            while ((lastMask & rb.Back()) != rb.Back())
            {
                lastMask <<= 1;
                lastMask |= 1;
            }

            do
            {
                NextBytes(rb);
                rb.Back() &= lastMask;
                r = new BigInteger(rb);
            }
            while (r >= range);

            return minInclusive + r;
        }

        public static implicit operator AnyRng(RandomNumberGenerator rng) => new CryptoRngWrapper(rng);
        public static implicit operator AnyRng(BlockDeriveBytes drbg) => new BlockDrbgWrapper(drbg);
        public static implicit operator AnyRng(DeriveBytes drbg) => new DrbgWrapper(drbg);
    }

    internal class CryptoRngWrapper : AnyRng
    {
        private readonly RandomNumberGenerator _rng;
        internal CryptoRngWrapper(RandomNumberGenerator rng) => _rng = rng;
        public override void NextBytes(byte[] buf) => _rng.GetBytes(buf);
    }

    internal class BlockDrbgWrapper : AnyRng
    {
        private readonly BlockDeriveBytes _rng;
        internal BlockDrbgWrapper(BlockDeriveBytes rng) => _rng = rng;
        public override void NextBytes(byte[] buf) => _rng.GetBytes(buf);
    }

    internal class DrbgWrapper : AnyRng
    {
        private readonly DeriveBytes _rng;
        internal DrbgWrapper(DeriveBytes rng) => _rng = rng;
        public override void NextBytes(byte[] buf) => Array.Copy(_rng.GetBytes(buf.Length), buf, buf.Length);
    }
}