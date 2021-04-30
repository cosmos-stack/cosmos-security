// ReSharper disable once CheckNamespace

namespace Cosmos.Security.Verification
{
    public static class BlakeFactory
    {
        public static IBlake Create(BlakeTypes type = BlakeTypes.Blake2B)
        {
            return Create(type, BlakeTable.Map(type));
        }

        public static IBlake Create(BlakeTypes type, BlakeConfig config)
        {
            return type switch
            {
                //BlakeTypes.Blake256 => new Blake1Function(config, BlakeTypes.Blake256),
                BlakeTypes.Blake512 => new Blake1Function(config, BlakeTypes.Blake512),
                BlakeTypes.Blake2S => new Blake2SFunction(config),
                BlakeTypes.Blake2B => new Blake2BFunction(config),
                _ => new Blake2BFunction(config)
            };
        }
    }
}