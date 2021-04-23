using System;

namespace Cosmos.Security.Verification
{
    public class JenkinsConfig
    {
        public int HashSizeInBits { get; internal set; } = 32;
        public UInt32 Seed { get; set; } = 0U;
        public UInt32 Seed2 { get; set; } = 0U;

        public JenkinsConfig Clone() => new()
        {
            HashSizeInBits = HashSizeInBits,
            Seed = Seed,
            Seed2 = Seed2
        };
    }
}