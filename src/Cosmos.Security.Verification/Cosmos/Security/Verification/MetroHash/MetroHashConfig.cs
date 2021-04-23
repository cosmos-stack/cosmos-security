using System;

namespace Cosmos.Security.Verification
{
    public class MetroHashConfig
    {
        public UInt64 Seed { get; set; } = 0;

        public MetroHashConfig Clone() => new() {Seed = Seed};
    }
}