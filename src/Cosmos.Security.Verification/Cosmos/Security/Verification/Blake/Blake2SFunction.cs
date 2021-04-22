using System;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using Cosmos.Security.Verification.Core;
using Org.BouncyCastle.Crypto.Digests;

// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Verification
{
    public partial class Blake2SFunction : StreamableHashFunctionBase
    {
        private readonly BlakeConfig _config;

        public Blake2SFunction(BlakeConfig config)
        {
            if (config == null)
                throw new ArgumentNullException(nameof(config));

            _config = config.Clone();
        }

        public BlakeConfig Config => _config.Clone();

        public override int HashSizeInBits => _config.HashSizeInBits;

        public override IBlockTransformer CreateBlockTransformer() => new BlockTransformer(_config);

        #region Internal Implementation of BlockTransformer

        private class BlockTransformer : BlockTransformerBase<BlockTransformer>
        {
            private int _hashSizeInBits;
            private BlakeConfig _config;

            private byte[] _hashValue;
            public BlockTransformer() { }

            public BlockTransformer(BlakeConfig config)
            {
                _hashSizeInBits = config.HashSizeInBits;
                _config = config;
            }

            protected override void CopyStateTo(BlockTransformer other)
            {
                base.CopyStateTo(other);

                other._hashSizeInBits = _hashSizeInBits;
                other._config = _config.Clone();

                other._hashValue = _hashValue;
            }

            protected override void TransformByteGroupsInternal(ArraySegment<byte> data)
            {
                using var hash = new Blake2sCryptoServiceProvider(_config);
                _hashValue = hash.ComputeHash(data.ToArray());
            }

            protected override IHashValue FinalizeHashValueInternal(CancellationToken cancellationToken)
            {
                return new HashValue(_hashValue, _hashSizeInBits);
            }
        }

        #endregion

        private class Blake2sCryptoServiceProvider : HashAlgorithm
        {
            private readonly Blake2sDigest _digest;

            public Blake2sCryptoServiceProvider(BlakeConfig config)
            {
                if (config is null || config.Key is null)
                    _digest = new Blake2sDigest();
                else
                    _digest = new Blake2sDigest(
                        config?.Key?.ToArray(),
                        32,
                        config?.Salt?.ToArray(),
                        config?.Personalization?.ToArray());
            }

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
    }
}