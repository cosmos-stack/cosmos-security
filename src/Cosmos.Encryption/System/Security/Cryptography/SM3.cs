/*
 * A copy of https://github.com/linnaea/Cryptography.GM
 *     Author: Linnaea Von Lavia
 *     Site: http://linnaea.moe/
 */

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.Primitives;
using Cryptography.GM;
using static Cryptography.GM.BitOps;

// ReSharper disable InconsistentNaming

namespace System.Security.Cryptography
{
    internal sealed class SM3 : HashAlgorithm
    {
        public override int HashSize => 256;
        private const ushort BlockSize = 512;

        private readonly byte[] _msgBuf = new byte[BlockSize / 8];
        private ushort _msgBufCount;

        private Bits256 _state;
        private ulong _blockCount;

        public SM3()
        {
            Initialize();
        }

        private static uint P0(uint v) => v ^ RotL32(v, 9) ^ RotL32(v, 17);
        private static uint P1(uint v) => v ^ RotL32(v, 15) ^ RotL32(v, 23);
        private static uint T(int j) => j < 16 ? 0x79cc4519u : 0x7a879d8au;
        private static uint FF(int j, uint x, uint y, uint z) => j < 16 ? x ^ y ^ z : (x & y) | (x & z) | (y & z);
        private static uint GG(int j, uint x, uint y, uint z) => j < 16 ? x ^ y ^ z : (x & y) | (~x & z);

        private void CompressOneBlock(ReadOnlySpan<byte> block)
        {
            _blockCount += 1;
            Span<uint> w = stackalloc uint[68];
            for (var i = 0; i < 16; i++)
            {
                w[i] = ReadU32Be(block.Slice(i * 4, 4));
            }

            for (var j = 16; j < 68; j++)
            {
                w[j] = P1(w[j - 16] ^ w[j - 9] ^ RotL32(w[j - 3], 15)) ^ RotL32(w[j - 13], 7) ^ w[j - 6];
            }

            Span<uint> wp = stackalloc uint[64];
            for (var j = 0; j < 64; j++)
            {
                wp[j] = w[j] ^ w[j + 4];
            }

            var (a, b, c, d, e, f, g, h) = _state;
            for (var j = 0; j < 64; j++)
            {
                var ss1 = RotL32(RotL32(a, 12) + e + RotL32(T(j), (byte) (j % 32)), 7);
                var ss2 = ss1 ^ RotL32(a, 12);
                var tt1 = FF(j, a, b, c) + d + ss2 + wp[j];
                var tt2 = GG(j, e, f, g) + h + ss1 + w[j];
                d = c;
                c = RotL32(b, 9);
                b = a;
                a = tt1;
                h = g;
                g = RotL32(f, 19);
                f = e;
                e = P0(tt2);
            }

            _state = (a, b, c, d, e, f, g, h) ^ _state;
        }

        private ReadOnlySpan<byte> CopyToBuffer(ReadOnlySpan<byte> buf, ref ulong nBits)
        {
            var toCopy = (ushort) Math.Min((ushort) (BlockSize - _msgBufCount), nBits);
            var r = BitCopy(buf, _msgBuf, _msgBufCount, toCopy);
            _msgBufCount += toCopy;
            nBits -= toCopy;
            return r;
        }

        public void HashCoreBits(ReadOnlySpan<byte> buf, ulong nBits)
        {
            while (nBits > 0)
            {
                if (_msgBufCount == 0 && nBits >= BlockSize)
                {
                    CompressOneBlock(buf.Slice(0, _msgBuf.Length));
                    buf = buf.Slice(_msgBuf.Length);
                    nBits -= BlockSize;
                }
                else
                {
                    buf = CopyToBuffer(buf, ref nBits);
                    if (_msgBufCount != BlockSize) continue;
                    CompressOneBlock(_msgBuf);
                    _msgBufCount = 0;
                }
            }
        }

#if NETSTANDARD2_1
        protected override void HashCore(ReadOnlySpan<byte> buf) => HashCoreBits(buf, (uint)buf.Length * 8);
#else
        private void HashCore(ReadOnlySpan<byte> buf) => HashCoreBits(buf, (uint) buf.Length * 8);
#endif

        public byte[] FinalizeHash()
        {
            var messageBits = _blockCount * BlockSize + _msgBufCount;
            HashCoreBits(new byte[] {0x80}, 1);
            byte[] finalBlock;
            uint finalBlockOffset;
            if (_msgBufCount > BlockSize - 64)
            {
                finalBlock = new byte[BlockSize / 8 + 8];
                finalBlockOffset = _msgBufCount - (BlockSize - 64u);
            }
            else
            {
                finalBlock = new byte[BlockSize / 8];
                finalBlockOffset = _msgBufCount;
            }

            WriteU64Be(finalBlock.AsSpan(finalBlock.Length - 8), messageBits);
            HashCoreBits(SliceBits(finalBlock, finalBlockOffset), (uint) finalBlock.Length * 8 - finalBlockOffset);

            var r = new byte[32];
            for (var i = 0; i < 32; i++)
            {
                r[i] = (byte) (Bits128) (_state >> (248 - i * 8));
            }

            return r;
        }

        protected override byte[] HashFinal() => FinalizeHash();

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
            => HashCore(array.AsSpan(ibStart, cbSize));

        public override void Initialize()
        {
            _state = (0x7380166fu, 0x4914b2b9u, 0x172442d7u, 0xda8a0600u, 0xa96f30bcu, 0x163138aau, 0xe38dee4du, 0xb0fb0e4e);
            _blockCount = 0;
            _msgBufCount = 0;
        }
    }

    [SuppressMessage("ReSharper", "IdentifierTypo")]
    internal sealed class HMACSM3 : GenericHMAC<SM3>
    {
        public HMACSM3(byte[] rgbKey) : base(new SM3(), 64, rgbKey) { }

        protected override byte[] FinalizeInnerHash() => Hasher.FinalizeHash();

        protected override void AddHashData(byte[] rgb, int ib, int cb)
            => Hasher.HashCoreBits(rgb.AsSpan(ib, cb), (uint) cb * 8);
    }
}