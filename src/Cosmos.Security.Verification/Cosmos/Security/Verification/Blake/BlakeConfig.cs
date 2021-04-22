using System.Collections.Generic;
using System.Linq;

// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Verification
{
    public class BlakeConfig
    {
        public int HashSizeInBits { get; set; } = 512;

        public IReadOnlyList<byte> Key { get; set; }

        public IReadOnlyList<byte> Salt { get; set; }

        public IReadOnlyList<byte> Personalization { get; set; }

        public BlakeConfig Clone() => new()
        {
            HashSizeInBits = HashSizeInBits,
            Key = Key?.ToArray(),
            Salt = Salt?.ToArray(),
            Personalization = Personalization?.ToArray(),
        };
    }
}