using System;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using Cosmos.Security.Verification.Core;

namespace Cosmos.Security.Verification.SHA
{
    public partial class ShaFunction : StreamableHashFunctionBase
    {
        private readonly ShaConfig _shaConfig;

        internal ShaFunction(ShaTypes type)
        {
            HashType = type;
            _shaConfig = ShaTable.Map(type);
        }

        public override int HashSizeInBits => _shaConfig.HashSizeInBits;

        public ShaTypes HashType { get; }

        public override IBlockTransformer CreateBlockTransformer() => new ShaBlockTransformer(_shaConfig);

        #region Internal Implementation of BlockTransformer

        private class ShaBlockTransformer : BlockTransformerBase<ShaBlockTransformer>
        {
            private int _hashSizeInBits;
            private Func<HashAlgorithm> _internalAlgorithmFactory;

            private byte[] _hashValue;

            public ShaBlockTransformer() { }

            public ShaBlockTransformer(ShaConfig config)
            {
                _hashSizeInBits = config.HashSizeInBits;
                _internalAlgorithmFactory = GetHashAlgorithm(config.Type);
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

            private static Func<HashAlgorithm> GetHashAlgorithm(ShaTypes type)
            {
                return type switch
                {
                    ShaTypes.Sha1 => () => new SHA1CryptoServiceProvider(),
                    ShaTypes.Sha224 => () => new SHA224CryptoServiceProvider(),
                    ShaTypes.Sha256 => () => new SHA256CryptoServiceProvider(),
                    ShaTypes.Sha384 => () => new SHA384CryptoServiceProvider(),
                    ShaTypes.Sha512 => () => new SHA512CryptoServiceProvider(),
                    ShaTypes.Sha512_224 => () => new SHA512L224CryptoServiceProvider(),
                    ShaTypes.Sha512_256 => () => new SHA512L256CryptoServiceProvider(),
                    _ => throw new ArgumentOutOfRangeException(nameof(type), type, null)
                };
            }
        }

        #endregion
    }
}