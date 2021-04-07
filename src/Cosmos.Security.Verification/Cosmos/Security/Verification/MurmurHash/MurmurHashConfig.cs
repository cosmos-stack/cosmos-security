using System;

namespace Cosmos.Security.Verification.MurmurHash
{
    public class MurmurHash1Config
    {
        /// <summary>
        /// Gets the seed.
        /// </summary>
        /// <value>
        /// The seed.
        /// </value>
        public UInt32 Seed { get; set; } = 0U;
    }

    public class MurmurHash2Config
    {
        /// <summary>
        /// Gets the desired hash size, in bits.
        /// </summary>
        /// <value>
        /// The desired hash size, in bits.
        /// </value>
        public int HashSizeInBits { get; set; } = 64;

        /// <summary>
        /// Gets the seed.
        /// </summary>
        /// <value>
        /// The seed.
        /// </value>
        public UInt64 Seed { get; set; } = 0UL;
    }

    public class MurmurHash3Config
    {
        /// <summary>
        /// Gets the desired hash size, in bits.
        /// </summary>
        /// <value>
        /// The desired hash size, in bits.
        /// </value>
        public int HashSizeInBits { get; set; } = 32;

        /// <summary>
        /// Gets the seed.
        /// </summary>
        /// <value>
        /// The seed.
        /// </value>
        public UInt32 Seed { get; set; } = 0U;
    }
}