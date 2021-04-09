using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using Cosmos.Reflection;
using Cosmos.Security.Verification.Core;

namespace Cosmos.Security.Verification.MurmurHash
{
    public partial class MurmurHash2Function : HashFunctionBase, IMurmurHash<MurmurHash2Config>
    {
        private const UInt32 _mixConstant32 = 0x5bd1e995;
        private const UInt64 _mixConstant64 = 0xc6a4a7935bd1e995;

        private static readonly IEnumerable<int> _validHashSizes = new HashSet<int>() {32, 64};

        private readonly MurmurHash2Config _config;

        internal MurmurHash2Function(MurmurHash2Config config)
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));

            if (!_validHashSizes.Contains(_config.HashSizeInBits))
                throw new ArgumentOutOfRangeException($"{nameof(config)}.{nameof(config.HashSizeInBits)}", _config.HashSizeInBits, $"{nameof(config)}.{nameof(config.HashSizeInBits)} must be contained within MurmurHash2.ValidHashSizes.");
        }

        public MurmurHash2Config Config => _config.DeepCopy(DeepCopyOptions.ExpressionCopier);

        public override int HashSizeInBits => _config.HashSizeInBits;

        protected override IHashValue ComputeHashInternal(ArraySegment<byte> data, CancellationToken cancellationToken)
        {
            return _config.HashSizeInBits switch
            {
                32 => ComputeHash32(data, cancellationToken),
                64 => ComputeHash64(data, cancellationToken),
                _ => throw new NotImplementedException()
            };
        }
    }
}