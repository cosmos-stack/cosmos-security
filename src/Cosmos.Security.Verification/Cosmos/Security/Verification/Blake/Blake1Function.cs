using System;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using Cosmos.Security.Verification.Core;

namespace Cosmos.Security.Verification
{
    public class Blake1Function : StreamableHashFunctionBase
    {
        private readonly BlakeConfig _config;

        public Blake1Function(BlakeConfig config, BlakeTypes type)
        {
            HashType = type;
            _config = config;
        }

        public BlakeConfig Config => _config.Clone();

        public override int HashSizeInBits => _config.HashSizeInBits;

        public BlakeTypes HashType { get; }

        public override IBlockTransformer CreateBlockTransformer() => new BlockTransformer(_config, HashType);

        #region Internal Implementation of BlockTransformer

        private class BlockTransformer : BlockTransformerBase<BlockTransformer>
        {
            private int _hashSizeInBits;
            private Func<HashAlgorithm> _internalAlgorithmFactory;
            private BlakeTypes _type;

            private byte[] _hashValue;

            public BlockTransformer() { }

            public BlockTransformer(BlakeConfig config, BlakeTypes type)
            {
                _type = type;
                _hashSizeInBits = config.HashSizeInBits;
                _internalAlgorithmFactory = GetHashAlgorithm(_type);
            }

            protected override void CopyStateTo(BlockTransformer other)
            {
                base.CopyStateTo(other);

                other._hashSizeInBits = _hashSizeInBits;
                other._internalAlgorithmFactory = _internalAlgorithmFactory;
                other._type = _type;

                other._hashValue = _hashValue;
            }

            protected override void TransformByteGroupsInternal(ArraySegment<byte> data)
            {
                using var hash = _internalAlgorithmFactory();
                _hashValue = hash.ComputeHash(data.ToArray());
            }

            protected override IHashValue FinalizeHashValueInternal(CancellationToken cancellationToken)
            {
                return new HashValue(_hashValue, _hashSizeInBits);
            }

            private static Func<HashAlgorithm> GetHashAlgorithm(BlakeTypes type)
            {
                return type switch
                {
                    //BlakeTypes.Blake256 => () => new Blake256(),
                    BlakeTypes.Blake512 => () => new Blake512()
                };
            }
        }

        #endregion

        #region Blake-256

        internal sealed class Blake256 : HashAlgorithm
        {
            private uint[] m_h = new uint[8];
            private uint[] m_s = new uint[4];

            // private uint[] m_t = new uint[2];
            private ulong m_t;

            private int m_nBufLen;
            private bool m_bNullT;
            private byte[] m_buf = new byte[64];

            private uint[] m_v = new uint[16];
            private uint[] m_m = new uint[16];

            private const int NbRounds = 8;

            private static readonly int[] g_sigma = new int[NbRounds * 16]
            {
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
                11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
                7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
                9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
                2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
                12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
                13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10
            };

            private static readonly uint[] g_cst = new uint[16]
            {
                0x243F6A88U, 0x85A308D3U, 0x13198A2EU, 0x03707344U,
                0xA4093822U, 0x299F31D0U, 0x082EFA98U, 0xEC4E6C89U,
                0x452821E6U, 0x38D01377U, 0xBE5466CFU, 0x34E90C6CU,
                0xC0AC29B7U, 0xC97C50DDU, 0x3F84D5B5U, 0xB5470917U
            };

            private static readonly byte[] g_padding = new byte[64]
            {
                0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            };

            public Blake256()
            {
                this.HashSizeValue = 256; // Hash size in bits
                Initialize();
            }

            /// <summary>
            /// Convert 4 bytes to an <c>UInt32</c> using big-endian.
            /// </summary>
            private static uint BytesToUInt32(byte[] pb, int iOffset)
            {
                return ((uint) pb[iOffset + 3] | ((uint) pb[iOffset + 2] << 8) |
                        ((uint) pb[iOffset + 1] << 16) | ((uint) pb[iOffset] << 24));
            }

            /// <summary>
            /// Convert an <c>UInt32</c> to 4 bytes using big-endian.
            /// </summary>
            private static void UInt32ToBytes(uint u, byte[] pbOut, int iOffset)
            {
                for (int i = 3; i >= 0; --i)
                {
                    pbOut[iOffset + i] = (byte) (u & 0xFF);
                    u >>= 8;
                }
            }

            private static uint RotateRight(uint u, int nBits)
            {
                return ((u >> nBits) | (u << (32 - nBits)));
            }

            private void G(int a, int b, int c, int d, int r, int i)
            {
                int p = (r << 4) + i;
                int p0 = g_sigma[p];
                int p1 = g_sigma[p + 1];

                m_v[a] += m_v[b] + (m_m[p0] ^ g_cst[p1]);
                m_v[d] = RotateRight(m_v[d] ^ m_v[a], 16);
                m_v[c] += m_v[d];
                m_v[b] = RotateRight(m_v[b] ^ m_v[c], 12);
                m_v[a] += m_v[b] + (m_m[p1] ^ g_cst[p0]);
                m_v[d] = RotateRight(m_v[d] ^ m_v[a], 8);
                m_v[c] += m_v[d];
                m_v[b] = RotateRight(m_v[b] ^ m_v[c], 7);
            }

            private void Compress(byte[] pbBlock, int iOffset)
            {
                for (int i = 0; i < 16; ++i)
                    m_m[i] = BytesToUInt32(pbBlock, iOffset + (i << 2));

                Array.Copy(m_h, m_v, 8);
                m_v[8] = m_s[0] ^ 0x243F6A88U;
                m_v[9] = m_s[1] ^ 0x85A308D3U;
                m_v[10] = m_s[2] ^ 0x13198A2EU;
                m_v[11] = m_s[3] ^ 0x03707344U;
                m_v[12] = 0xA4093822U;
                m_v[13] = 0x299F31D0U;
                m_v[14] = 0x082EFA98U;
                m_v[15] = 0xEC4E6C89U;

                if (!m_bNullT)
                {
                    uint uLen = (uint) (m_t & 0xFFFFFFFFU);
                    m_v[12] ^= uLen;
                    m_v[13] ^= uLen;
                    uLen = (uint) ((m_t >> 32) & 0xFFFFFFFFU);
                    m_v[14] ^= uLen;
                    m_v[15] ^= uLen;
                }

                for (int r = 0; r < NbRounds; ++r)
                {
                    G(0, 4, 8, 12, r, 0);
                    G(1, 5, 9, 13, r, 2);
                    G(2, 6, 10, 14, r, 4);
                    G(3, 7, 11, 15, r, 6);
                    G(3, 4, 9, 14, r, 14);
                    G(2, 7, 8, 13, r, 12);
                    G(0, 5, 10, 15, r, 8);
                    G(1, 6, 11, 12, r, 10);
                }

                for (int i = 0; i < 8; ++i) m_h[i] ^= m_v[i];
                for (int i = 0; i < 8; ++i) m_h[i] ^= m_v[i + 8];

                for (int i = 0; i < 4; ++i) m_h[i] ^= m_s[i];
                for (int i = 0; i < 4; ++i) m_h[i + 4] ^= m_s[i];
            }

            public override void Initialize()
            {
                m_h[0] = 0x6A09E667U;
                m_h[1] = 0xBB67AE85U;
                m_h[2] = 0x3C6EF372U;
                m_h[3] = 0xA54FF53AU;
                m_h[4] = 0x510E527FU;
                m_h[5] = 0x9B05688CU;
                m_h[6] = 0x1F83D9ABU;
                m_h[7] = 0x5BE0CD19U;

                Array.Clear(m_s, 0, m_s.Length);

                // Array.Clear(m_t, 0, m_t.Length);
                m_t = 0;

                m_nBufLen = 0;
                m_bNullT = false;

                Array.Clear(m_buf, 0, m_buf.Length);
            }

            protected override void HashCore(byte[] array, int ibStart, int cbSize)
            {
                int iOffset = ibStart;
                int nFill = 64 - m_nBufLen;

                if ((m_nBufLen > 0) && (cbSize >= nFill))
                {
                    Array.Copy(array, iOffset, m_buf, m_nBufLen, nFill);
                    m_t += 512;
                    Compress(m_buf, 0);
                    iOffset += nFill;
                    cbSize -= nFill;
                    m_nBufLen = 0;
                }

                while (cbSize >= 64)
                {
                    m_t += 512;
                    Compress(array, iOffset);
                    iOffset += 64;
                    cbSize -= 64;
                }

                if (cbSize > 0)
                {
                    Array.Copy(array, iOffset, m_buf, m_nBufLen, cbSize);
                    m_nBufLen += cbSize;
                }
                else m_nBufLen = 0;
            }

            protected override byte[] HashFinal()
            {
                byte[] pbMsgLen = new byte[8];
                ulong uLen = m_t + ((ulong) m_nBufLen << 3);
                UInt32ToBytes((uint) ((uLen >> 32) & 0xFFFFFFFFU), pbMsgLen, 0);
                UInt32ToBytes((uint) (uLen & 0xFFFFFFFFU), pbMsgLen, 4);

                if (m_nBufLen == 55)
                {
                    m_t -= 8;
                    HashCore(new byte[1] {0x81}, 0, 1);
                }
                else
                {
                    if (m_nBufLen < 55)
                    {
                        if (m_nBufLen == 0) m_bNullT = true;
                        m_t -= 440UL - ((ulong) m_nBufLen << 3);
                        HashCore(g_padding, 0, 55 - m_nBufLen);
                    }
                    else
                    {
                        m_t -= 512UL - ((ulong) m_nBufLen << 3);
                        HashCore(g_padding, 0, 64 - m_nBufLen);
                        m_t -= 440UL;
                        HashCore(g_padding, 1, 55);
                        m_bNullT = true;
                    }

                    HashCore(new byte[1] {0x01}, 0, 1);
                    m_t -= 8;
                }

                m_t -= 64;
                HashCore(pbMsgLen, 0, 8);

                byte[] pbDigest = new byte[32];
                for (int i = 0; i < 8; ++i)
                    UInt32ToBytes(m_h[i], pbDigest, i << 2);
                return pbDigest;
            }
        }
        
        #endregion

        #region Blake-512
        
        internal sealed class Blake512 : HashAlgorithm
        {
            private const int _roundCount = 16;
            private ulong[] _h = new ulong[8];
            private ulong[] _s = new ulong[4];
            private ulong _t;
            private int _buffLength;
            private bool _nullT;
            private byte[] _messageBuffer = new byte[128];
            private ulong[] _v = new ulong[16];
            private ulong[] _m = new ulong[16];

            private static readonly int[] _sigma = new int[_roundCount * 16]
            {
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
                11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
                7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
                9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
                2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
                12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
                13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
                6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
                10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
                11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
                7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
                9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
                2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9
            };

            private static readonly ulong[] _c = new ulong[16]
            {
                0x243F6A8885A308D3UL,
                0x13198A2E03707344UL,
                0xA4093822299F31D0UL,
                0x082EFA98EC4E6C89UL,
                0x452821E638D01377UL,
                0xBE5466CF34E90C6CUL,
                0xC0AC29B7C97C50DDUL,
                0x3F84D5B5B5470917UL,
                0x9216D5D98979FB1BUL,
                0xD1310BA698DFB5ACUL,
                0x2FFD72DBD01ADFB7UL,
                0xB8E1AFED6A267E96UL,
                0xBA7C9045F12C7F99UL,
                0x24A19947B3916CF7UL,
                0x0801F2E2858EFC16UL,
                0x636920D871574E69UL
            };

            private static readonly byte[] _padding = new byte[128]
            {
                0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            };

            private static readonly ulong[] _iv = new ulong[8]
            {
                0x6A09E667F3BCC908UL,
                0xBB67AE8584CAA73BUL,
                0x3C6EF372FE94F82BUL,
                0xA54FF53A5F1D36F1UL,
                0x510E527FADE682D1UL,
                0x9B05688C2B3E6C1FUL,
                0x1F83D9ABFB41BD6BUL,
                0x5BE0CD19137E2179UL
            };

            public Blake512()
            {
                HashSizeValue = 512;
                Initialize();
            }

            public override void Initialize()
            {
                Array.Copy(_iv, 0, _h, 0, _h.Length);
                Array.Clear(_s, 0, _s.Length);
                Array.Clear(_messageBuffer, 0, _messageBuffer.Length);
                _nullT = false;
                _buffLength = 0;
                _t = 0;
            }

            protected override void HashCore(byte[] array, int ibStart, int cbSize)
            {
                int offset = ibStart; // с какой позции читать байты
                int fill = 128 - _buffLength; // размер свободного место для заполнения

                if (_buffLength > 0 && cbSize >= fill)
                {
                    Array.Copy(array, offset, _messageBuffer, _buffLength, fill);
                    _t += 1024;
                    Compress(_messageBuffer, 0);
                    offset += fill;
                    cbSize -= fill;
                    _buffLength = 0;
                }

                // бежим и поблочно сжимаем полученные данные
                while (cbSize >= 128)
                {
                    _t += 1024;
                    Compress(array, offset);
                    offset += 128;
                    cbSize -= 128;
                }

                // если что-то осталось, то запоминаем это в буфер
                if (cbSize > 0)
                {
                    Array.Copy(array, offset, _messageBuffer, _buffLength, cbSize);
                    _buffLength += cbSize;
                }
                else
                {
                    _buffLength = 0;
                }
            }

            protected override byte[] HashFinal()
            {
                byte[] pbMsg = new byte[16];
                UInt64ToBytes(_t + ((ulong) _buffLength << 3), pbMsg, 8);

                if (_buffLength == 111)
                {
                    _t -= 8;
                    HashCore(new byte[1] {0x81}, 0, 1);
                }
                else
                {
                    if (_buffLength < 111)
                    {
                        if (_buffLength == 0) _nullT = true;
                        _t -= 888UL - ((ulong) _buffLength << 3);
                        HashCore(_padding, 0, 111 - _buffLength);
                    }
                    else
                    {
                        _t -= 1024UL - ((ulong) _buffLength << 3);
                        HashCore(_padding, 0, 128 - _buffLength);
                        _t -= 888UL;
                        HashCore(_padding, 1, 111);
                        _nullT = true;
                    }

                    HashCore(new byte[1] {0x01}, 0, 1);
                    _t -= 8;
                }

                _t -= 128;
                HashCore(pbMsg, 0, 16);

                byte[] pbDigest = new byte[64];
                for (int i = 0; i < 8; ++i)
                    UInt64ToBytes(_h[i], pbDigest, i << 3);
                return pbDigest;
            }

            private static ulong Shift(ulong u, int nBits)
            {
                return ((u >> nBits) | (u << (64 - nBits)));
            }

            private void G(int a, int b, int c, int d, int r, int i)
            {
                int p = (r << 4) + i;
                int p0 = _sigma[p];
                int p1 = _sigma[p + 1];

                _v[a] += _v[b] + (_m[p0] ^ _c[p1]);
                _v[d] = Shift(_v[d] ^ _v[a], 32);
                _v[c] += _v[d];
                _v[b] = Shift(_v[b] ^ _v[c], 25);
                _v[a] += _v[b] + (_m[p1] ^ _c[p0]);
                _v[d] = Shift(_v[d] ^ _v[a], 16);
                _v[c] += _v[d];
                _v[b] = Shift(_v[b] ^ _v[c], 11);
            }

            private void SetMessage(byte[] block, int offset)
            {
                for (int i = 0; i < 16; ++i)
                    _m[i] = BytesToUInt64(block, offset + (i << 3));
            }

            private void SetVariables()
            {
                Array.Copy(_h, _v, 8);
                _v[8] = _s[0] ^ _c[0];
                _v[9] = _s[1] ^ _c[1];
                _v[10] = _s[2] ^ _c[2];
                _v[11] = _s[3] ^ _c[3];
                _v[12] = _c[4];
                _v[13] = _c[5];
                _v[14] = _c[6];
                _v[15] = _c[7];

                if (!_nullT)
                {
                    _v[12] ^= _t;
                    _v[13] ^= _t;
                    // _v[14] ^= _t[1];
                    // _v[15] ^= _t[1];
                }
            }

            private void SetHashValues()
            {
                for (int i = 0; i < 8; ++i)
                    _h[i] ^= _v[i];

                for (int i = 0; i < 8; ++i)
                    _h[i] ^= _v[i + 8];

                for (int i = 0; i < 4; ++i)
                    _h[i] ^= _s[i];

                for (int i = 0; i < 4; ++i)
                    _h[i + 4] ^= _s[i];
            }

            private void Compress(byte[] block, int offset)
            {
                SetMessage(block, offset);
                SetVariables();

                for (int r = 0; r < _roundCount; ++r)
                {
                    G(0, 4, 8, 12, r, 0);
                    G(1, 5, 9, 13, r, 2);
                    G(2, 6, 10, 14, r, 4);
                    G(3, 7, 11, 15, r, 6);

                    G(3, 4, 9, 14, r, 14);
                    G(2, 7, 8, 13, r, 12);
                    G(0, 5, 10, 15, r, 8);
                    G(1, 6, 11, 12, r, 10);
                }

                SetHashValues();
            }

            private static void UInt64ToBytes(ulong u, byte[] pbOut, int iOffset)
            {
                for (int i = 7; i >= 0; --i)
                {
                    pbOut[iOffset + i] = (byte) (u & 0xFF);
                    u >>= 8;
                }
            }

            private static ulong BytesToUInt64(byte[] pb, int iOffset)
            {
                return ((ulong) pb[iOffset + 7] | ((ulong) pb[iOffset + 6] << 8) |
                        ((ulong) pb[iOffset + 5] << 16) | ((ulong) pb[iOffset + 4] << 24) |
                        ((ulong) pb[iOffset + 3] << 32) | ((ulong) pb[iOffset + 2] << 40) |
                        ((ulong) pb[iOffset + 1] << 48) | ((ulong) pb[iOffset] << 56));
            }
        }

        #endregion
    }
}