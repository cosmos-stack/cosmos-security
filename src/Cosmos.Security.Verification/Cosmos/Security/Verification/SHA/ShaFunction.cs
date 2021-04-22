using System;
#if NETFRAMEWORK
using System.Linq;
#endif
using System.Security.Cryptography;
using System.Threading;
using Cosmos.Security.Verification.Core;
using Org.BouncyCastle.Crypto.Digests;

// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Verification
{
    public class ShaFunction : StreamableHashFunctionBase
    {
        internal ShaFunction(ShaTypes type)
        {
            HashType = type;
            HashSizeInBits = (int) type % 1000;
        }

        public override int HashSizeInBits { get; }

        public ShaTypes HashType { get; }

        public override IBlockTransformer CreateBlockTransformer() => new ShaBlockTransformer(HashType);

        #region Internal Implementation of BlockTransformer

        private class ShaBlockTransformer : BlockTransformerBase<ShaBlockTransformer>
        {
            private int _hashSizeInBits;
            private Func<HashAlgorithm> _internalAlgorithmFactory;

            private byte[] _hashValue;

            public ShaBlockTransformer() { }

            public ShaBlockTransformer(ShaTypes type)
            {
                _hashSizeInBits = (int) type % 1000;
                _internalAlgorithmFactory = GetHashAlgorithm(type, _hashSizeInBits);
            }

            protected override void CopyStateTo(ShaBlockTransformer other)
            {
                base.CopyStateTo(other);

                other._hashSizeInBits = _hashSizeInBits;
                other._internalAlgorithmFactory = _internalAlgorithmFactory;

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

            private static Func<HashAlgorithm> GetHashAlgorithm(ShaTypes type, int hashSizeInBits)
            {
                return type switch
                {
                    ShaTypes.Sha1 => () => new SHA1CryptoServiceProvider(),
                    ShaTypes.Sha224 => () => new SHA224CryptoServiceProvider(),
                    ShaTypes.Sha256 => () => new SHA256CryptoServiceProvider(),
                    ShaTypes.Sha384 => () => new SHA384CryptoServiceProvider(),
                    ShaTypes.Sha512 => () => new SHA512CryptoServiceProvider(),
                    ShaTypes.Sha512Bit224 => () => new SHA512tCryptoServiceProvider(hashSizeInBits),
                    ShaTypes.Sha512Bit256 => () => new SHA512tCryptoServiceProvider(hashSizeInBits),
                    ShaTypes.Sha3Bit224 => () => new SHA3CryptoServiceProvider(hashSizeInBits),
                    ShaTypes.Sha3Bit256 => () => new SHA3CryptoServiceProvider(hashSizeInBits),
                    ShaTypes.Sha3Bit384 => () => new SHA3CryptoServiceProvider(hashSizeInBits),
                    ShaTypes.Sha3Bit512 => () => new SHA3CryptoServiceProvider(hashSizeInBits),
                    _ => () => new SHA1CryptoServiceProvider()
                };
            }
        }

        #endregion

        #region Internal HashAlgorithm Implementation

        /// <summary>
        /// SHA224 Crypto Service Provider
        /// </summary>
        private class SHA224CryptoServiceProvider : HashAlgorithm
        {
            private readonly Sha224Digest _digest;

            public SHA224CryptoServiceProvider()
            {
                _digest = new Sha224Digest();
            }

            public override int HashSize => 224;

            public override void Initialize()
            {
                HashValue = new byte[_digest.GetDigestSize()];
            }

            protected override void HashCore(byte[] array, int ibStart, int cbSize)
            {
                if (HashValue is null)
                    Initialize();
                _digest.BlockUpdate(array, ibStart, cbSize);
            }

            protected override byte[] HashFinal()
            {
                _digest.DoFinal(HashValue, 0);
                return HashValue;
            }
        }

        /// <summary>
        /// SHA512/t Crypto Service Provider
        /// </summary>
        private class SHA512tCryptoServiceProvider : HashAlgorithm
        {
            private readonly Sha512tDigest _digest;
            private readonly int _hashSize;

            public SHA512tCryptoServiceProvider(int hashSize)
            {
                _hashSize = hashSize;
                _digest = new Sha512tDigest(hashSize);
            }

            public override int HashSize => _hashSize;

            public override void Initialize()
            {
                HashValue = new byte[_digest.GetDigestSize()];
            }

            protected override void HashCore(byte[] array, int ibStart, int cbSize)
            {
                if (HashValue is null)
                    Initialize();
                _digest.BlockUpdate(array, ibStart, cbSize);
            }

            protected override byte[] HashFinal()
            {
                _digest.DoFinal(HashValue, 0);
                return HashValue;
            }
        }

        /// <summary>
        /// SHA3 Crypto Service Provider
        /// </summary>
        private class SHA3CryptoServiceProvider : HashAlgorithm
        {
            private readonly Sha3Digest _digest;
            private readonly int _hashSize;

            public SHA3CryptoServiceProvider(int hashSize)
            {
                _hashSize = hashSize;
                _digest = new Sha3Digest(hashSize);
            }

            public override int HashSize => _hashSize;

            public override void Initialize()
            {
                HashValue = new byte[_digest.GetDigestSize()];
            }

            protected override void HashCore(byte[] array, int ibStart, int cbSize)
            {
                if (HashValue is null)
                    Initialize();
                _digest.BlockUpdate(array, ibStart, cbSize);
            }

            protected override byte[] HashFinal()
            {
                _digest.DoFinal(HashValue, 0);
                return HashValue;
            }
        }

        #endregion
    }
}