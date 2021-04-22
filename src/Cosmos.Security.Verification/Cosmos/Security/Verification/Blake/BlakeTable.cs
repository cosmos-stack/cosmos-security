// ReSharper disable once CheckNamespace

namespace Cosmos.Security.Verification
{
    internal static class BlakeTable
    {
        public static BlakeConfig Map(BlakeTypes type)
        {
            return type switch
            {
                //BlakeTypes.Blake256 => new BlakeConfig {HashSizeInBits = 256},
                BlakeTypes.Blake512 => new BlakeConfig {HashSizeInBits = 512},
                BlakeTypes.Blake2S => new BlakeConfig {HashSizeInBits = 256},
                BlakeTypes.Blake2B => new BlakeConfig {HashSizeInBits = 512},
            };
        }
    }
}