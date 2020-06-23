/*
 * A copy of https://github.com/linnaea/Cryptography.GM
 *     Author: Linnaea Von Lavia
 *     Site: http://linnaea.moe/
 */

using System;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Numerics;
// ReSharper disable once RedundantUsingDirective
using System.Security.Cryptography;
using System.Security.Cryptography.Primitives;

// ReSharper disable once CheckNamespace
namespace Cryptography.GM.ECMath
{
    internal class FpParameter : IEcParameter
    {
        public EcPoint G { get; }
        public FpCurve Curve { get; }
        public ushort BitLength { get; }
        public BigInteger H => BigInteger.One;
        public BigInteger N { get; }

        public FpParameter(FpCurve curve, EcPoint g, BigInteger n)
        {
            Curve = curve;
            G = g;
            N = n;
            BitLength = (ushort) n.BitLength();
        }

        IEcCurve IEcParameter.Curve => Curve;

#if NETSTANDARD1_6 || NETSTANDARD2_0 || NETSTANDARD2_1
        ECCurve IEcParameter.ToEcCurve() => this;

        public static implicit operator ECCurve(FpParameter p) =>
            new ECCurve {
                CurveType = ECCurve.ECCurveType.PrimeShortWeierstrass,
                Prime = p.Curve.P.ToByteArrayUBe(),
                A = p.Curve.A.ToByteArrayUBe(),
                B = p.Curve.B.ToByteArrayUBe(),
                G = p.G,
                Cofactor = new byte[] {1},
                Order = p.N.ToByteArrayUBe()
            };
#endif

        // ReSharper disable once InconsistentNaming
        [SuppressMessage("ReSharper", "StringLiteralTypo")]
        public static readonly FpParameter SM2StandardParam = new FpParameter(
            new FpCurve(
                BigInteger.Parse("0FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
                    NumberStyles.HexNumber),
                BigInteger.Parse("0FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
                    NumberStyles.HexNumber),
                BigInteger.Parse("028E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
                    NumberStyles.HexNumber)
            ),
            new EcPoint(
                BigInteger.Parse("032C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
                    NumberStyles.HexNumber),
                BigInteger.Parse("0BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",
                    NumberStyles.HexNumber)
            ),
            BigInteger.Parse("0FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
                NumberStyles.HexNumber)
        );
    }

    internal class FpCurve : IEcCurve
    {
        private readonly BigInteger _inv2;
        private readonly BigInteger _eulerPower;

        public BigInteger P { get; }
        public BigInteger A { get; }
        public BigInteger B { get; }
        public ushort BitLength { get; }

        public FpCurve(BigInteger p, BigInteger a, BigInteger b)
        {
            P = p;
            A = a;
            B = b;
            BitLength = (ushort) p.BitLength();
            _eulerPower = (p - 1) / 2;
            _inv2 = 2;
            _inv2 = _inv2.InvMod(p);
        }

        private bool IsQuadraticResidue(BigInteger v) => BigInteger.ModPow(v, _eulerPower, P).IsOne;

        private BigInteger Sqrt(BigInteger x, AnyRng rng)
        {
            if (!IsQuadraticResidue(x))
                throw new InvalidOperationException();

            BigInteger z;
            do
            {
                z = rng.NextBigInt(BigInteger.One, P);
            }
            while (IsQuadraticResidue(z));

            var q = _eulerPower;
            ulong s = 1;
            while (q.IsEven)
            {
                s++;
                q /= 2;
            }

            var m = s;
            var c = BigInteger.ModPow(z, q, P);
            var t = BigInteger.ModPow(x, q, P);
            var r = BigInteger.ModPow(x, q / 2 + 1, P);
            while (true)
            {
                if (t.IsZero)
                {
                    return BigInteger.Zero;
                }

                if (t.IsOne)
                {
                    return r;
                }

                ulong i = 1;
                while (i < m)
                {
                    if (BigInteger.ModPow(t, BigInteger.ModPow(2, i, P), P).IsOne)
                        break;
                    i++;
                }

                if (i == m)
                    throw new InvalidOperationException();

                var b = BigInteger.ModPow(c, BigInteger.ModPow(2, m - i - 1, P), P);
                m = i;
                c = b * b % P;
                t = t * b * b % P;
                r = r * b % P;
            }
        }

        public BigInteger SolveY(BigInteger x, bool lsbSet, AnyRng rng)
        {
            var rhs = x * x * x + A * x + B;
            rhs %= P;
            var r = Sqrt(rhs, rng);

            if (r.IsZero) return r;
            if (lsbSet == r.IsEven) r = P - r;
            return r;
        }

        private JacobianEcPoint Double(JacobianEcPoint p)
        {
            if (p.Inf) return p;
            if (p.Y.IsZero) return JacobianEcPoint.Infinity;

            var a = p.X * p.Y * p.Y % P;
            var b = _inv2 * (3 * p.X * p.X + A * BigInteger.ModPow(p.Z, 4, P)) % P;
            var x = b * b - 2 * a;
            var y = b * (a - x) - BigInteger.ModPow(p.Y, 4, P);
            var z = p.Y * p.Z;
            x -= (x / P - (x.Sign < 0 ? 1 : 0)) * P;
            y -= (y / P - (y.Sign < 0 ? 1 : 0)) * P;
            z -= (z / P - (z.Sign < 0 ? 1 : 0)) * P;
            return new JacobianEcPoint
            {
                X = x, Y = y, Z = z
            };
        }

        private JacobianEcPoint Negate(JacobianEcPoint p)
        {
            if (p.Inf) return p;
            if (p.Y.IsZero) return p;

            return new JacobianEcPoint
            {
                X = p.X, Y = P - p.Y, Z = p.Z
            };
        }

        private JacobianEcPoint Add(JacobianEcPoint p1, JacobianEcPoint p2)
        {
            if (p1.Inf) return p2;
            if (p2.Inf) return p1;

            var a = p1.X * p2.Z * p2.Z % P;
            var b = p2.X * p1.Z * p1.Z % P;
            var c = p1.Y * p2.Z * p2.Z * p2.Z % P;
            var d = p2.Y * p1.Z * p1.Z * p1.Z % P;
            var e = a - b;
            var f = c - d;

            if (e.IsZero)
            {
                return f.IsZero ? Double(p1) : JacobianEcPoint.Infinity;
            }

            var x = f * f - e * e * e - 2 * b * e * e;
            var y = f * (b * e * e - x) - d * e * e * e;
            var z = p1.Z * p2.Z * e;
            x -= (x / P - (x.Sign < 0 ? 1 : 0)) * P;
            y -= (y / P - (y.Sign < 0 ? 1 : 0)) * P;
            z -= (z / P - (z.Sign < 0 ? 1 : 0)) * P;
            return new JacobianEcPoint
            {
                X = x, Y = y, Z = z
            };
        }

        private static (byte[], byte[]) ToNafBytes(BigInteger i1, BigInteger i2)
        {
            var k1 = i1.ToNAFBytes();
            var k2 = i2.ToNAFBytes();
            var kl = Math.Max(k1.Length, k2.Length);
            Array.Resize(ref k1, kl);
            Array.Resize(ref k2, kl);

            return (k1, k2);
        }

        public JacobianEcPoint MultiplyAndAdd(BigInteger k, JacobianEcPoint p, BigInteger m, JacobianEcPoint s, AnyRng rng)
        {
            if (k.Sign < 0)
            {
                k = -k;
                p = Negate(p);
            }

            if (m.Sign < 0)
            {
                m = -m;
                s = Negate(s);
            }

            if (k.IsZero) return Multiply(m, s, rng);
            if (m.IsZero) return Multiply(k, p, rng);
            if (k.IsOne) return Add(p, Multiply(m, s, rng));
            if (m.IsOne) return Add(s, Multiply(k, p, rng));

            var (kk, mm) = ToNafBytes(k, m);
            var i = 0;
            while (i < kk.Length - 1)
            {
                if (kk[i] != 0 || mm[i] != 0)
                {
                    i++;
                    continue;
                }

                switch (mm[i + 1])
                {
                    case 0:
                        mm[i + 1] = 0x01;
                        mm[i] = 0xE0;
                        break;
                    case 0x0F:
                        mm[i + 1] = 0xF0;
                        mm[i] = 0x20;
                        break;
                    case 0x01:
                        mm[i + 1] = 0x10;
                        mm[i] = 0xE0;
                        break;
                    case 0xF0:
                        mm[i + 1] = 0x0F;
                        mm[i] = 0xE0;
                        break;
                    case 0x10:
                        mm[i + 1] = 0x01;
                        mm[i] = 0x20;
                        break;
                    default:
                        throw new Exception();
                }
            }

            var lut = new[]
            {
                // T[x,y] = lut[7x+y-1]
                s, Double(s), JacobianEcPoint.Infinity, Double(Double(s)),
                Add(p, Negate(Double(s))), Add(p, Negate(s)), p, Add(p, s), Add(p, Double(s)),
                JacobianEcPoint.Infinity, JacobianEcPoint.Infinity,
                Add(Double(p), Negate(Double(s))), Add(Double(p), Negate(s)),
                Double(p), Add(Double(p), s), Add(Double(p), Double(s))
            };

            var r = lut[kk.Back().NafValue() * 7 + mm.Back().NafValue() - 1];
            for (i = kk.Length - 2; i >= 0; i--)
            {
                r = Double(Double(r));
                if (kk[i] == 0)
                {
                    if (mm[i].NafValue() < 0)
                    {
                        r = Add(r, Negate(lut[-mm[i].NafValue() - 1]));
                    }
                    else
                    {
                        r = Add(r, lut[mm[i].NafValue() - 1]);
                    }
                }
                else if (kk[i].NafValue() < 0)
                {
                    r = Add(r, Negate(lut[-kk[i].NafValue() * 7 - mm[i].NafValue() - 1]));
                }
                else
                {
                    r = Add(r, lut[kk[i].NafValue() * 7 + mm[i].NafValue() - 1]);
                }
            }

            return r;
        }

        public JacobianEcPoint Multiply(BigInteger k, JacobianEcPoint p, AnyRng rng)
        {
            if (k.Sign < 0)
            {
                k = -k;
                p = Negate(p);
            }

            if (k.IsZero) return JacobianEcPoint.Infinity;
            if (k.IsOne) return p;

            var ks = rng.NextBigInt(BigInteger.One, k);
            // return MultiplyAndAdd(ks, p, k - ks, p, rng);
            var (k1, k2) = ToNafBytes(k - ks, ks);
            var i = 0;
            while (i < k1.Length - 1)
            {
                var c = k1[i].NafValue() + k2[i].NafValue();
                if (c != 0)
                {
                    i++;
                    continue;
                }

                if (k2[i + 1].NafValue() > 0)
                {
                    k2[i + 1] = (byte) ((k2[i + 1].H() << 4) | ((k2[i + 1].L() - 1) & 0xF));
                    k2[i] = (byte) (((k2[i].H() + 2) << 4) | (k2[i].L() & 0xF));
                }
                else
                {
                    k2[i + 1] = (byte) ((k2[i + 1].H() << 4) | ((k2[i + 1].L() + 1) & 0xF));
                    k2[i] = (byte) (((k2[i].H() - 2) << 4) | (k2[i].L() & 0xF));
                }
            }

            var lut = new[]
            {
                JacobianEcPoint.Infinity,
                p,
                Double(p),
                Add(Double(p), p),
                Double(Double(p))
            };

            var r = lut[k1.Back().NafValue() + k2.Back().NafValue()];
            for (i = k1.Length - 2; i >= 0; i--)
            {
                var c = k1[i].NafValue() + k2[i].NafValue();
                r = Add(Double(Double(r)), c < 0 ? Negate(lut[-c]) : lut[c]);
            }

            return r;
        }

        public EcPoint ToAffine(JacobianEcPoint jp)
        {
            if (jp.Inf)
                return EcPoint.Infinity;
            if (jp.Affine)
                return new EcPoint(jp.X, jp.Y);
            BigInteger x, y;
            var zc = (jp.Z * jp.Z % P).InvMod(P);
            var zd = (jp.Z * jp.Z * jp.Z % P).InvMod(P);
            x = jp.X * zc % P;
            y = jp.Y * zd % P;
            return new EcPoint(x, y);
        }

        public bool ValidatePoint(EcPoint p)
        {
            var lhs = p.Y * p.Y;
            var rhs = p.X * p.X * p.X % P + A * p.X + B;
            return lhs % P == rhs % P;
        }
    }

    internal struct JacobianEcPoint
    {
        public static readonly JacobianEcPoint Infinity = default;

        public bool Inf => Z.IsZero;
        public bool Affine => Z.IsOne;
        public BigInteger X { get; set; }
        public BigInteger Y { get; set; }
        public BigInteger Z { get; set; }

        public static implicit operator JacobianEcPoint(EcPoint p)
        {
            if (p.Inf)
                return Infinity;

            return new JacobianEcPoint
            {
                X = p.X,
                Y = p.Y,
                Z = BigInteger.One
            };
        }

#if NETSTANDARD1_6 || NETSTANDARD2_0 || NETSTANDARD2_1
        public static implicit operator JacobianEcPoint(ECPoint p)
        {
            if (p.X == null || p.Y == null)
                return Infinity;

            return new JacobianEcPoint {
                X = p.X.AsBigUIntBe(),
                Y = p.Y.AsBigUIntBe(),
                Z = BigInteger.One
            };
        }
#endif

        public override string ToString() =>
            Inf ? "EcPoint{O}" : Affine ? $"EcPoint{{X={X:X}, Y={Y:X}}}" : $"EcPoint{{X={X:X}, Y={Y:X}, Z={Z:X}}}";
    }
}