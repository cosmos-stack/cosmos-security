using System;

// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Verification
{
    public class SpookyHashConfig
    {
        public int HashSizeInBits { get; internal set; } = 128;

        public UInt64 Seed { get; set; } = 0UL;

        public UInt64 Seed2 { get; set; } = 0UL;

        public SpookyHashConfig Clone() => new()
        {
            HashSizeInBits = HashSizeInBits,
            Seed = Seed,
            Seed2 = Seed2
        };
    }
}