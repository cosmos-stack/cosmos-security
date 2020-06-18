/*
 * A copy of https://github.com/linnaea/Cryptography.GM
 *     Author: Linnaea Von Lavia
 *     Site: http://linnaea.moe/
 */

using System.Buffers;

namespace System.Security.Cryptography.Primitives
{
    internal abstract class BlockDeriveBytes : DeriveBytes
    {
#if NET451
        private byte[] _remaining = new byte[0];
#else
        private byte[] _remaining = Array.Empty<byte>();
#endif

        public abstract int BlockSize { get; }
        public abstract void NextBlock(Span<byte> buf);

        public void GetBytes(byte[] buf)
        {
            var cb = buf.Length;
            if (cb < _remaining.Length)
            {
                Array.Copy(_remaining, 0, buf, 0, cb);
                Array.Copy(_remaining, cb, _remaining, 0, _remaining.Length - cb);
                Array.Resize(ref _remaining, _remaining.Length - cb);
                return;
            }

            Array.Copy(_remaining, buf, _remaining.Length);
            var offset = _remaining.Length;
#if NET451
            _remaining = new byte[0];
#else
            _remaining = Array.Empty<byte>();
#endif

            while (offset < cb)
            {
                var toCopy = Math.Min(cb - offset, BlockSize);
                if (toCopy == BlockSize)
                {
                    NextBlock(buf.AsSpan(offset));
                }
                else
                {
                    var bounce = ArrayPool<byte>.Shared.Rent(BlockSize);
                    _remaining = new byte[BlockSize - toCopy];
                    NextBlock(bounce.AsSpan(0, BlockSize));
                    Array.Copy(bounce, 0, buf, offset, toCopy);
                    Array.Copy(bounce, toCopy, _remaining, 0, _remaining.Length);
                    ArrayPool<byte>.Shared.Return(bounce);
                }

                offset += toCopy;
            }
        }

        public override byte[] GetBytes(int cb)
        {
            var ret = new byte[cb];
            GetBytes(ret);
            return ret;
        }

        public override void Reset()
        {
#if NET451
            _remaining = new byte[0];
#else
            _remaining = Array.Empty<byte>();
#endif
        }
    }
}