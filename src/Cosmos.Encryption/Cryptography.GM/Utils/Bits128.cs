// ReSharper disable once CheckNamespace

/*
 * A copy of https://github.com/linnaea/Cryptography.GM
 *     Author: Linnaea Von Lavia
 *     Site: http://linnaea.moe/
 */

namespace Cryptography.GM
{
    internal struct Bits128
    {
        private ulong _lo;
        private ulong _hi;

        public static explicit operator ulong(Bits128 v) => v._lo;
        public static implicit operator Bits128((ulong hi, ulong lo) pair) => new Bits128 {_lo = pair.lo, _hi = pair.hi};
        public static implicit operator (ulong hi, ulong lo)(Bits128 v) => (v._hi, v._lo);

        public static implicit operator (uint hh, uint hl, uint lh, uint ll)(Bits128 v)
            => ((uint) (v._hi >> 32), (uint) v._hi, (uint) (v._lo >> 32), (uint) v._lo);

        public static implicit operator Bits128((uint hh, uint hl, uint lh, uint ll) v) => new Bits128
        {
            _lo = (ulong) v.lh << 32 | v.ll, _hi = (ulong) v.hh << 32 | v.hl
        };

        public static explicit operator Bits128(int v) => new Bits128
        {
            _lo = (ulong) v,
            _hi = (ulong) (v >> 31)
        };

        public static Bits128 operator >>(Bits128 l, int r)
        {
            r %= 128;
            if (r >= 64)
            {
                return new Bits128
                {
                    _lo = l._hi >> (r - 64)
                };
            }

            if (r > 0)
            {
                var hi = l._hi;
                l._hi >>= r;
                l._lo >>= r;
                l._lo |= hi << (64 - r);
            }

            return l;
        }

        public static Bits128 operator <<(Bits128 l, int r)
        {
            r %= 128;
            if (r >= 64)
            {
                return new Bits128
                {
                    _hi = l._lo << (r - 64)
                };
            }

            if (r > 0)
            {
                var lo = l._lo;
                l._hi <<= r;
                l._lo <<= r;
                l._hi |= lo >> (64 - r);
            }

            return l;
        }

        public static Bits128 operator ^(Bits128 l, Bits128 r) => new Bits128
        {
            _lo = l._lo ^ r._lo,
            _hi = l._hi ^ r._hi
        };

        public static Bits128 operator &(Bits128 l, Bits128 r) => new Bits128
        {
            _lo = l._lo & r._lo,
            _hi = l._hi & r._hi
        };

        public static Bits128 operator |(Bits128 l, Bits128 r) => new Bits128
        {
            _lo = l._lo | r._lo,
            _hi = l._hi | r._hi
        };

        public static Bits128 operator |(Bits128 l, ulong r) => new Bits128
        {
            _lo = l._lo | r,
            _hi = l._hi
        };
    }

    internal struct Bits256
    {
        private Bits128 _lo;
        private Bits128 _hi;

        public void Deconstruct(out uint hhh, out uint hhl, out uint hlh, out uint hll,
            out uint lhh, out uint lhl, out uint llh, out uint lll)
        {
            var tuple = ((uint, uint, uint, uint, uint, uint, uint, uint)) this;
            (hhh, hhl, hlh, hll, lhh, lhl, llh, lll) = tuple;
        }

        public static explicit operator Bits128(Bits256 v) => v._lo;
        public static implicit operator Bits256((Bits128 hi, Bits128 lo) pair) => new Bits256 {_lo = pair.lo, _hi = pair.hi};
        public static implicit operator (Bits128 hi, Bits128 lo)(Bits256 v) => (v._hi, v._lo);

        public static implicit operator (uint hhh, uint hhl, uint hlh, uint hll, uint lhh, uint lhl, uint llh, uint lll)(Bits256 v)
        {
            (uint hh, uint hl, uint lh, uint ll) l = v._lo;
            (uint hh, uint hl, uint lh, uint ll) h = v._hi;
            return (h.hh, h.hl, h.lh, h.ll, l.hh, l.hl, l.lh, l.ll);
        }

        public static implicit operator Bits256((uint hhh, uint hhl, uint hlh, uint hll, uint lhh, uint lhl, uint llh, uint lll) v)
            => new Bits256
            {
                _hi = (v.hhh, v.hhl, v.hlh, v.hll),
                _lo = (v.lhh, v.lhl, v.llh, v.lll)
            };

        public static Bits256 operator >>(Bits256 l, int r)
        {
            r %= 256;
            if (r >= 128)
            {
                return new Bits256
                {
                    _lo = l._hi >> (r - 128)
                };
            }

            if (r > 0)
            {
                var hi = l._hi;
                l._hi >>= r;
                l._lo >>= r;
                l._lo |= hi << (128 - r);
            }

            return l;
        }

        public static Bits256 operator <<(Bits256 l, int r)
        {
            r %= 256;
            if (r >= 128)
            {
                return new Bits256
                {
                    _hi = l._lo << (r - 128)
                };
            }

            if (r > 0)
            {
                var lo = l._lo;
                l._hi <<= r;
                l._lo <<= r;
                l._hi |= lo >> (128 - r);
            }

            return l;
        }

        public static Bits256 operator ^(Bits256 l, Bits256 r) => new Bits256
        {
            _lo = l._lo ^ r._lo,
            _hi = l._hi ^ r._hi
        };

        public static Bits256 operator |(Bits256 l, ulong r) => new Bits256
        {
            _lo = l._lo | r,
            _hi = l._hi
        };
    }
}