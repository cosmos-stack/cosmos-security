/*
 * A copy of https://github.com/linnaea/Cryptography.GM
 *     Author: Linnaea Von Lavia
 *     Site: http://linnaea.moe/
 */

#if !NET451

using System.Buffers;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography.Primitives;
using Cryptography.GM;
using Cryptography.GM.ECMath;

namespace System.Security.Cryptography
{
    // ReSharper disable once InconsistentNaming
    internal class SM2 : AsymmetricAlgorithm
    {
        private readonly AnyRng _rng;
        private HashAlgorithm _hash;
        private IEcParameter _param;
        private BigInteger _privateKey;
        private EcPoint _pubKey;
        private byte[] _ident;

        private SM2(IEcParameter param, HashAlgorithm hash, AnyRng rng)
        {
#if NETSTANDARD2_0 || NETSTANDARD2_1
            if (!hash.CanReuseTransform || !hash.CanTransformMultipleBlocks || hash.InputBlockSize != 1)
                throw new ArgumentException(nameof(hash));
#endif

            _rng = rng;
            _hash = hash;
            _param = param;
            _ident = Array.Empty<byte>();
        }

#pragma warning disable 108
        public static SM2 Create() => Create(new SM3(), RandomNumberGenerator.Create());
        public static SM2 Create(HashAlgorithm hash) => Create(hash, RandomNumberGenerator.Create());
        public static SM2 Create(AnyRng rng) => Create(new SM3(), rng);
        public static SM2 Create(HashAlgorithm hash, AnyRng rng) => new SM2(FpParameter.SM2StandardParam, hash, rng);
#pragma warning restore 108

        public byte[] Ident
        {
            get => (byte[]) _ident.Clone();
            set
            {
#if NET451
                _ident = value ?? new byte[0];
#else
                _ident = value ?? Array.Empty<byte>();
#endif
                _ident = _ident.Length > ushort.MaxValue / 8
                    ? throw new CryptographicException()
                    : (byte[]) _ident.Clone();
            }
        }

        public bool HasPublicKey => !_pubKey.Inf;
        public bool HasPrivateKey => !_privateKey.IsZero;
        public int KeyBytes => (KeySize + 7) / 8;

        public override int KeySize
        {
            get => Math.Max(_param.BitLength, _param.Curve.BitLength);
            set
            {
                if (value != KeySize) throw new NotSupportedException();
                KeySizeValue = value;
            }
        }

        public override KeySizes[] LegalKeySizes => new[]
        {
            new KeySizes(KeySize, KeySize, 0)
        };

        #region GM/T 0003.1-2012 Generals

        public EcKeyPair GenerateKeyPair()
        {
            var pk = _rng.NextBigInt(BigInteger.One, _param.N - 1);
            ImportPrivateKey(pk);
            return ExportKey();
        }

        public void ImportPrivateKey(BigInteger d)
        {
            if (d.Sign <= 0 || d >= _param.N - 1)
            {
                throw new CryptographicException();
            }

            _privateKey = d;
            _pubKey = _param.Curve.ToAffine(_param.Curve.Multiply(d, _param.G, _rng));
        }

        public void ImportPublicKey(EcPoint jp)
        {
            if (!_param.Curve.ValidatePoint(jp))
            {
                throw new CryptographicException();
            }

            if (_pubKey != jp)
            {
                _privateKey = 0;
            }

            _pubKey = jp;
        }

        public void ImportKey(EcKeyPair kp)
        {
            if (!kp.Param.N.IsZero)
            {
                _param = kp.Param;
            }

            if (!kp.D.IsZero)
            {
                ImportPrivateKey(kp.D);
                return;
            }

            if (!kp.Q.Inf)
            {
                ImportPublicKey(kp.Q);
                return;
            }

            throw new InvalidOperationException();
        }

        public EcKeyPair ExportKey() =>
            new EcKeyPair
            {
                D = _privateKey,
                Q = _pubKey,
                Param = _param
            };

        public (EcPoint Point, int Bytes) PointFromBytes(ReadOnlySpan<byte> p)
        {
            var x = p.Slice(1, KeyBytes).AsBigUIntBe();
            switch (p[0])
            {
                case 2:
                case 3:
                {
                    return (new EcPoint(x, _param.Curve.SolveY(x, p[0] == 3, _rng)), KeyBytes + 1);
                }
                case 4:
                case 6:
                case 7:
                {
                    var y = p.Slice(1 + KeyBytes, KeyBytes).AsBigUIntBe();
                    var point = new EcPoint(x, y);

                    if (p[0] != 4)
                    {
                        if (y != _param.Curve.SolveY(x, p[0] == 7, _rng))
                        {
                            throw new InvalidDataException();
                        }
                    }
                    else
                    {
                        if (!_param.Curve.ValidatePoint(point))
                        {
                            throw new InvalidDataException();
                        }
                    }

                    return (point, KeyBytes * 2 + 1);
                }
                default:
                    throw new InvalidDataException();
            }
        }

        public static byte[] ZValue(IEcParameter param, HashAlgorithm hash, ReadOnlySpan<byte> identity, EcPoint pubKey)
        {
            if (identity.Length > ushort.MaxValue / 8)
                throw new ArgumentOutOfRangeException(nameof(identity));

            if (pubKey.Inf)
                throw new ArgumentOutOfRangeException(nameof(pubKey));

            var pkBytes = (param.Curve.BitLength + 7) / 8;

#if NETSTANDARD2_0 || NETSTANDARD2_1
            hash.Initialize();
            var z = ArrayPool<byte>.Shared.Rent(2 + identity.Length);
            BitOps.WriteU16Be(z, (ushort) (identity.Length * 8));
            identity.CopyTo(z.AsSpan(2));
            hash.TransformBlock(z, 0, identity.Length + 2, null, 0);
            ArrayPool<byte>.Shared.Return(z);
            hash.TransformBlock(param.Curve.A.ToByteArrayUBe(pkBytes), 0, pkBytes, null, 0);
            hash.TransformBlock(param.Curve.B.ToByteArrayUBe(pkBytes), 0, pkBytes, null, 0);
            hash.TransformBlock(param.G.X.ToByteArrayUBe(pkBytes), 0, pkBytes, null, 0);
            hash.TransformBlock(param.G.Y.ToByteArrayUBe(pkBytes), 0, pkBytes, null, 0);
            hash.TransformBlock(pubKey.X.ToByteArrayUBe(pkBytes), 0, pkBytes, null, 0);
            hash.TransformFinalBlock(pubKey.Y.ToByteArrayUBe(pkBytes), 0, pkBytes);
            return hash.Hash;
#else
            var z = ArrayPool<byte>.Shared.Rent(2 + identity.Length + pkBytes * 6);
            BitOps.WriteU16Be(z, (ushort) (identity.Length * 8));
            identity.CopyTo(z.AsSpan(2));
            param.Curve.A.ToByteArrayUBe(pkBytes).CopyTo(z, 2 + identity.Length);
            param.Curve.B.ToByteArrayUBe(pkBytes).CopyTo(z, 2 + identity.Length + pkBytes);
            param.G.X.ToByteArrayUBe(pkBytes).CopyTo(z, 2 + identity.Length + pkBytes * 2);
            param.G.Y.ToByteArrayUBe(pkBytes).CopyTo(z, 2 + identity.Length + pkBytes * 3);
            pubKey.X.ToByteArrayUBe(pkBytes).CopyTo(z, 2 + identity.Length + pkBytes * 4);
            pubKey.Y.ToByteArrayUBe(pkBytes).CopyTo(z, 2 + identity.Length + pkBytes * 5);

            var h = hash.ComputeHash(z, 0, 2 + identity.Length + pkBytes * 6);
            ArrayPool<byte>.Shared.Return(z);
            return h;
#endif
        }

        #endregion

        #region GM/T 0003.2-2012 Digital Signature

        public (BigInteger r, BigInteger s) SignHash(BigInteger e)
        {
            if (!HasPrivateKey) throw new InvalidOperationException();

            BigInteger r, s;

            do
            {
                var k = _rng.NextBigInt(BigInteger.One, _param.N);
                var xy1 = _param.Curve.Multiply(k, _param.G, _rng);
                r = (e + _param.Curve.ToAffine(xy1).X) % _param.N;
                s = (1 + _privateKey).InvMod(_param.N) * (k - r * _privateKey);
                s -= (s / _param.N - (s.Sign < 0 ? 1 : 0)) * _param.N;
            }
            while (s.IsZero);

            return (r, s);
        }

        public bool VerifyHash(BigInteger r, BigInteger s, BigInteger e)
        {
            if (!HasPublicKey) throw new InvalidOperationException();
            if (r.IsZero || s.IsZero) return false;
            if (r >= _param.N || s >= _param.N) return false;

            var t = (r + s) % _param.N;
            if (t.IsZero) return false;

            var xy1 = _param.Curve.MultiplyAndAdd(s, _param.G, t, _pubKey, _rng);
            return (e + _param.Curve.ToAffine(xy1).X) % _param.N == r;
        }

        public byte[] SignData(ReadOnlySpan<byte> message)
        {
            var z = ZValue(_param, _hash, _ident, _pubKey);
            var hashBytes = z.Length;
            var m = ArrayPool<byte>.Shared.Rent(hashBytes + message.Length);
            z.CopyTo(m, 0);
            message.CopyTo(m.AsSpan(hashBytes));
            var h = _hash.ComputeHash(m, 0, hashBytes + message.Length).AsBigUIntBe();
            var (r, s) = SignHash(h);
            ArrayPool<byte>.Shared.Return(m);

            return r.ToByteArrayUBe(KeyBytes).Concat(s.ToByteArrayUBe(KeyBytes)).ToArray();
        }

        public bool VerifyData(ReadOnlySpan<byte> sig, ReadOnlySpan<byte> message)
        {
            if (sig.Length != KeyBytes * 2) return false;
            var r = sig.Slice(0, KeyBytes).AsBigUIntBe();
            var s = sig.Slice(KeyBytes, KeyBytes).AsBigUIntBe();
            var z = ZValue(_param, _hash, _ident, _pubKey);
            var hashBytes = z.Length;
            var m = ArrayPool<byte>.Shared.Rent(hashBytes + message.Length);
            z.CopyTo(m, 0);
            message.CopyTo(m.AsSpan(hashBytes));
            var h = _hash.ComputeHash(m, 0, hashBytes + message.Length).AsBigUIntBe();
            var v = VerifyHash(r, s, h);
            ArrayPool<byte>.Shared.Return(m);

            return v;
        }

        #endregion

        #region GM/T 0003.3-2012 Key Exchange

        public SM2KeyExchange ContinueKeyExchange(BigInteger eKey, bool responder)
        {
            if (!HasPrivateKey) throw new InvalidOperationException();
            if (!HasPublicKey) throw new InvalidOperationException();

            var z = ZValue(_param, _hash, _ident, _pubKey);
            return new SM2KeyExchange(_rng, _hash, z, _privateKey, responder, new EcKeyPair
            {
                D = eKey, Param = _param,
                Q = _param.Curve.ToAffine(_param.Curve.Multiply(eKey, _param.G, _rng))
            });
        }

        public SM2KeyExchange StartKeyExchange(bool responder)
            => ContinueKeyExchange(_rng.NextBigInt(BigInteger.One, _param.N), responder);

        #endregion

        #region GM/T 0003.4-2012 Encryption

        private XorStreamCipherTransform<SM2DeriveBytes> CreateCipher(EcPoint xy)
        {
            var key = ArrayPool<byte>.Shared.Rent(KeyBytes * 2);
            xy.X.ToByteArrayUBe(KeyBytes).CopyTo(key, 0);
            xy.Y.ToByteArrayUBe(KeyBytes).CopyTo(key, KeyBytes);
            var kdf = new SM2DeriveBytes(key.AsSpan(0, KeyBytes * 2), _hash);
            var cipher = new XorStreamCipherTransform<SM2DeriveBytes>(kdf);
            ArrayPool<byte>.Shared.Return(key);

            return cipher;
        }

        private byte[] ComputeC3(EcPoint xy, ReadOnlySpan<byte> message)
        {
            var c3Data = ArrayPool<byte>.Shared.Rent(message.Length + KeyBytes * 2);
            xy.X.ToByteArrayUBe(KeyBytes).CopyTo(c3Data, 0);
            message.CopyTo(c3Data.AsSpan(KeyBytes));
            xy.Y.ToByteArrayUBe(KeyBytes).CopyTo(c3Data, message.Length + KeyBytes);
            var c3 = _hash.ComputeHash(c3Data, 0, message.Length + KeyBytes * 2);
            ArrayPool<byte>.Shared.Return(c3Data);

            return c3;
        }

        public (EcPoint c1, byte[] c3, byte[] c2) EncryptMessage(ReadOnlySpan<byte> message)
        {
            if (!HasPublicKey)
                throw new InvalidOperationException();

            if (_param.Curve.Multiply(_param.H, _pubKey, _rng).Inf)
                throw new CryptographicException();

            var k = _rng.NextBigInt(BigInteger.One, _param.N);
            var c1 = _param.Curve.ToAffine(_param.Curve.Multiply(k, _param.G, _rng));
            var xy = _param.Curve.ToAffine(_param.Curve.Multiply(k, _pubKey, _rng));

            var cipher = CreateCipher(xy);
            var c2 = new byte[message.Length];
            cipher.TransformBits(message, c2, c2.Length * 8);

            return (c1, ComputeC3(xy, message), c2);
        }

        public byte[] DecryptMessage(EcPoint c1, ReadOnlySpan<byte> c3, ReadOnlySpan<byte> c2)
        {
            if (!HasPrivateKey) throw new InvalidOperationException();
            if (!_param.Curve.ValidatePoint(c1)) throw new CryptographicException();
            if (_param.Curve.Multiply(_param.H, c1, _rng).Inf) throw new CryptographicException();

            var xy = _param.Curve.ToAffine(_param.Curve.Multiply(_privateKey, c1, _rng));

            var cipher = CreateCipher(xy);
            var message = new byte[c2.Length];
            cipher.TransformBits(c2, message, c2.Length * 8);

            if (!c3.SequenceEquals(ComputeC3(xy, message))) throw new CryptographicException();

            return message;
        }

        public byte[] EncryptData(ReadOnlySpan<byte> data, EcPointFormat pointFormat = EcPointFormat.Mixed)
        {
            var (c1, c3, c2) = EncryptMessage(data);
            var c1Bytes = c1.ToBytes(pointFormat, KeyBytes);
            Array.Resize(ref c2, c2.Length + c3.Length + c1Bytes.Length);
            Array.Copy(c2, 0, c2, c3.Length + c1Bytes.Length, data.Length);
            Array.Copy(c1Bytes, 0, c2, 0, c1Bytes.Length);
            Array.Copy(c3, 0, c2, c1Bytes.Length, c3.Length);
            return c2;
        }

        public byte[] DecryptData(ReadOnlySpan<byte> data)
        {
            var (c1, c1Length) = PointFromBytes(data);
            data = data.Slice(c1Length);

            var c3 = data.Slice(0, (_hash.HashSize + 7) / 8);
            var c2 = data.Slice(c3.Length);

            return DecryptMessage(c1, c3, c2);
        }

        #endregion
    }
}

#endif