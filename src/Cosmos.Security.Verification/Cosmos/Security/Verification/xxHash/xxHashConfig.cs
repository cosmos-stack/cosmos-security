// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Verification
{
    public class xxHashConfig
    {
        public int HashSizeInBits { get; internal set; } = 32;

        public ulong Seed { get; set; } = 0UL;

        /// <summary>
        /// Makes a deep clone of current instance.
        /// </summary>
        /// <returns>A deep clone of the current instance.</returns>
        public xxHashConfig Clone() => new()
        {
            HashSizeInBits = HashSizeInBits,
            Seed = Seed
        };
    }
}