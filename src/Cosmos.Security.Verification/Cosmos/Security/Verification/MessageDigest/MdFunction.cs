using System;
using System.Threading;
using Cosmos.Reflection;
using Cosmos.Security.Verification.Core;
// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Verification
{
    public partial class MdFunction : StreamableHashFunctionBase
    {
        private readonly MdConfig _mdConfig;

        internal MdFunction(MdTypes type)
        {
            HashType = type;
            _mdConfig = MdTable.Map(type);
        }

        internal MdFunction(Md6Options options)
        {
            HashType = MdTypes.Md6Custom;
            _mdConfig = options;
        }

        public override int HashSizeInBits => _mdConfig.HashSizeInBits;

        public MdTypes HashType { get; }

        public override IBlockTransformer CreateBlockTransformer() => new MdBlockTransformer(_mdConfig);

        #region Internal Implementationof BlockTransformer

        private class MdBlockTransformer : BlockTransformerBase<MdBlockTransformer>
        {
            private int _hashSizeInBits;
            private MdTypes _mdType;
            private TrimOptions _trimOptions;

            private IMessageDigestWorker _worker;

            private byte[] _hashValue;

            public MdBlockTransformer() { }

            public MdBlockTransformer(MdConfig config)
            {
                _hashSizeInBits = config.HashSizeInBits;
                _mdType = config.Type;

                _worker = config.Type switch
                {
                    MdTypes.Md2 => _worker = new Md2Worker(),
                    MdTypes.Md4 => _worker = new Md4Worker(),
                    MdTypes.Md5 => _worker = new Md5Worker(_mdType),
                    MdTypes.Md5Bit16 => _worker = new Md5Worker(_mdType),
                    MdTypes.Md5Bit32 => _worker = new Md5Worker(_mdType),
                    MdTypes.Md5Bit64 => _worker = new Md5Worker(_mdType),
                    MdTypes.Md6 => _worker = new Md6Worker(config),
                    MdTypes.Md6Bit128 => _worker = new Md6Worker(config),
                    MdTypes.Md6Bit256 => _worker = new Md6Worker(config),
                    MdTypes.Md6Bit512 => _worker = new Md6Worker(config),
                    MdTypes.Md6Custom => _worker = new Md6Worker(config),
                    _ => null
                };
                
                _trimOptions = config.GetTrimOptions();
            }

            protected override void CopyStateTo(MdBlockTransformer other)
            {
                base.CopyStateTo(other);

                other._hashSizeInBits = _hashSizeInBits;
                other._mdType = _mdType;
                other._trimOptions = _trimOptions.DeepCopy();

                other._hashValue = _hashValue;
            }

            protected override void TransformByteGroupsInternal(ArraySegment<byte> data)
            {
                _hashValue = _worker?.Hash(data);
            }

            protected override IHashValue FinalizeHashValueInternal(CancellationToken cancellationToken)
            {
                return new HashValue(_hashValue, _hashSizeInBits, _trimOptions);
            }
        }

        private interface IMessageDigestWorker
        {
            byte[] Hash(ReadOnlySpan<byte> buff);
        }

        #endregion
    }
}