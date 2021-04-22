using Cosmos.Security.Verification.Core;
using Factory = Cosmos.Security.Verification.BlakeFactory;

namespace Cosmos.Security.Verification
{
    public static class Blake
    {
        public static StreamableHashFunctionBase Create(BlakeTypes type = BlakeTypes.Blake2B) => Factory.Create(type);

        public static StreamableHashFunctionBase Create(BlakeTypes type, BlakeConfig config) => Factory.Create(type, config);
    }

    public static class Blake512
    {
        public static Blake1Function Create() => new(BlakeTable.Map(BlakeTypes.Blake512), BlakeTypes.Blake512);
        public static Blake1Function Create(BlakeConfig config) => new(config, BlakeTypes.Blake512);
    }

    public static class Blake2S
    {
        public static Blake2SFunction Create() => new(BlakeTable.Map(BlakeTypes.Blake2S));
        public static Blake2SFunction Create(BlakeConfig config) => new(config);
    }

    public static class Blake2B
    {
        public static Blake2BFunction Create() => new(BlakeTable.Map(BlakeTypes.Blake2B));
        public static Blake2BFunction Create(BlakeConfig config) => new(config);
    }
}