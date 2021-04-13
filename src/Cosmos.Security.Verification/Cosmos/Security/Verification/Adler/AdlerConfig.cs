// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Verification
{
    /// <summary>
    /// ADLER Hash Config
    /// </summary>
    public class AdlerConfig
    {
        /// <summary>
        /// Length of the produced Adler value, in bits.
        /// </summary>
        public int HashSizeInBits { get; internal set; }

        public uint Mod32 { get; internal set; }
        
        public ulong Mod64 { get; internal set; }

        public uint NMax { get; internal set; }

        public int MaxPart { get; internal set; }
    }
}