using System;
#if NETFRAMEWORK
using System.Linq;
#endif
using System.Security.Cryptography;
using System.Threading;
using Cosmos.Security.Verification.Core;

// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Verification
{
    public class HmacFunction : StreamableHashFunctionBase
    {
        private readonly HmacConfig _hmacConfig;

        internal HmacFunction(HmacTypes type, byte[] key)
        {
            _hmacConfig = HmacTable.Map(type);
            HashType = type;
            Key = key;
        }

        public override int HashSizeInBits => _hmacConfig.HashSizeInBits;

        public HmacTypes HashType { get; }

        public byte[] Key { get; set; }

        public override IBlockTransformer CreateBlockTransformer() => new HmacBlockTransformer(_hmacConfig, Key);

        #region Internal Implementation of BlockTransformer

        private class HmacBlockTransformer : BlockTransformerBase<HmacBlockTransformer>
        {
            private int _hashSizeInBits;
            private Func<KeyedHashAlgorithm> _internalAlgorithmFactory;
            private byte[] _key;

            private byte[] _hashValue;

            public HmacBlockTransformer() { }

            public HmacBlockTransformer(HmacConfig config, byte[] key)
            {
                _hashSizeInBits = config.HashSizeInBits;
                _internalAlgorithmFactory = config.HashAlgorithmFactory;
                _key = key;
            }

            protected override void CopyStateTo(HmacBlockTransformer other)
            {
                base.CopyStateTo(other);

                other._hashSizeInBits = _hashSizeInBits;
                other._internalAlgorithmFactory = _internalAlgorithmFactory;
                other._key = _key;

                other._hashValue = _hashValue;
            }

            protected override void TransformByteGroupsInternal(ArraySegment<byte> data)
            {
                using var hash = _internalAlgorithmFactory();
                hash.Key = _key;
                _hashValue = hash.ComputeHash(data.ToArray());
            }

            protected override IHashValue FinalizeHashValueInternal(CancellationToken cancellationToken)
            {
                return new HashValue(_hashValue, _hashSizeInBits);
            }
        }

        #endregion
    }
}