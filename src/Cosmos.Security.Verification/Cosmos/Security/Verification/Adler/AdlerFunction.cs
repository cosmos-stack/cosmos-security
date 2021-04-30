using System;
using System.Threading;
using Cosmos.Security.Verification.Core;

// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Verification
{
    /// <summary>
    /// ADLER Hash Function
    /// </summary>
    internal partial class AdlerFunction : StreamableHashFunctionBase, IAdler
    {
        private readonly AdlerConfig _adlerConfig;

        internal AdlerFunction(AdlerTypes type)
        {
            HashType = type;
            _adlerConfig = AdlerTable.Map(type);
        }

        public override int HashSizeInBits => _adlerConfig.HashSizeInBits;

        public AdlerTypes HashType { get; }

        public override IBlockTransformer CreateBlockTransformer() => new AdlerBlockTransformer(_adlerConfig);

        #region Internal Implementationof BlockTransformer

        private class AdlerBlockTransformer : BlockTransformerBase<AdlerBlockTransformer>
        {
            private int _hashSizeInBits;
            private uint _n_max;
            private int _max_part;

            private IAdlerWorker _worker;

            private byte[] _hashValue;

            public AdlerBlockTransformer() { }

            public AdlerBlockTransformer(AdlerConfig config)
            {
                _hashSizeInBits = config.HashSizeInBits;
                _n_max = config.NMax;
                _max_part = config.MaxPart;

                _worker = _hashSizeInBits switch
                {
                    32 => new Adler32Worker(config.Mod32, _n_max, _hashSizeInBits),
                    64 => new Adler64Worker(config.Mod64, _n_max, _max_part, _hashSizeInBits),
                    _ => null
                };
            }

            protected override void CopyStateTo(AdlerBlockTransformer other)
            {
                base.CopyStateTo(other);

                other._hashSizeInBits = _hashSizeInBits;
                other._n_max = _n_max;
                other._max_part = _max_part;

                other._hashValue = _hashValue;
            }

            protected override void TransformByteGroupsInternal(ArraySegment<byte> data)
            {
                _hashValue = _worker?.Hash(data);
            }

            protected override IHashValue FinalizeHashValueInternal(CancellationToken cancellationToken)
            {
                return new HashValue(_hashValue, _hashSizeInBits);
            }
        }

        private interface IAdlerWorker
        {
            public byte[] Hash(ReadOnlySpan<byte> buff);
        }

        #endregion
    }
}