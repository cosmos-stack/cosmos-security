using System;
using System.Collections.Generic;
using System.Linq;
using Cosmos.Reflection;
using Cosmos.Security.Verification.Core;
// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Verification
{
    public partial class MurmurHash3Function : StreamableHashFunctionBase, IStreamableMurmurHah<MurmurHash3Config>
    {
        private const UInt32 c1_32 = 0xcc9e2d51;
        private const UInt32 c2_32 = 0x1b873593;

        private const UInt64 c1_128 = 0x87c37b91114253d5;
        private const UInt64 c2_128 = 0x4cf5ad432745937f;

        private static readonly IEnumerable<int> _validHashSizes = new HashSet<int>() {32, 128};

        private readonly MurmurHash3Config _config;

        internal MurmurHash3Function(MurmurHash3Config config)
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));

            if (!_validHashSizes.Contains(_config.HashSizeInBits))
                throw new ArgumentOutOfRangeException($"{nameof(config)}.{nameof(config.HashSizeInBits)}", _config.HashSizeInBits, $"{nameof(config)}.{nameof(config.HashSizeInBits)} must be contained within MurmurHash3.ValidHashSizes.");
        }

        public MurmurHash3Config Config => _config.DeepCopy(DeepCopyOptions.ExpressionCopier);

        public override int HashSizeInBits => _config.HashSizeInBits;

        public override IBlockTransformer CreateBlockTransformer()
        {
            switch (_config.HashSizeInBits)
            {
                case 32:
                    return new BlockTransformer32((UInt32) _config.Seed);

                case 128:
                    return new BlockTransformer128(_config.Seed);

                default:
                    throw new NotImplementedException();
            }
        }
    }
}