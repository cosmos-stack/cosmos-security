using Cosmos.Security.Verification.Core;
using Factory = Cosmos.Security.Verification.BlakeFactory;

namespace Cosmos.Security.Verification
{
    public static class Blake
    {
        public static IBlake Create(BlakeTypes type = BlakeTypes.Blake2B) => Factory.Create(type);

        public static IBlake Create(BlakeTypes type, BlakeConfig config) => Factory.Create(type, config);
    }

    public static class Blake512
    {
        public static IBlake Create() => new Blake1Function(BlakeTable.Map(BlakeTypes.Blake512), BlakeTypes.Blake512);
        public static IBlake Create(BlakeConfig config) => new Blake1Function(config, BlakeTypes.Blake512);
    }

    public static class Blake2S
    {
        public static IBlake Create() => new Blake2SFunction(BlakeTable.Map(BlakeTypes.Blake2S));
        public static IBlake Create(BlakeConfig config) => new Blake2SFunction(config);
    }

    public static class Blake2B
    {
        public static IBlake Create() => new Blake2BFunction(BlakeTable.Map(BlakeTypes.Blake2B));
        public static IBlake Create(BlakeConfig config) => new Blake2BFunction(config);
    }
}