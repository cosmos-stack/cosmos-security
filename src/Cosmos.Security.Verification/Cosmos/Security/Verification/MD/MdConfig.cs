using System;
using Cosmos.Security.Verification.Core;
// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Verification
{
    public class MdConfig
    {
        /// <summary>
        /// Length of the produced Message Digest value, in bits.
        /// </summary>
        public int HashSizeInBits { get; internal set; }

        /// <summary>
        /// Message Digest Algorithm type of the value.
        /// </summary>
        public MdTypes Type { get; internal set; }

        /// <summary>
        /// Mode control, [0, 64], be used for MD6
        /// </summary>
        public uint ModeControl { get; internal set; }

        /// <summary>
        /// Number of Round, be used for MD6 <br />
        /// default value: <br /> without key = 40 + d/4 <br /> with key = max(80, 40 + d/4)
        /// </summary>
        public uint NumberOfRound { get; internal set; }

        /// <summary>
        /// Key, be used for MD6
        /// </summary>
        public string Key { get; set; } = "";

        /// <summary>
        /// To flag the value of key is HEX string or not, be used for MD6
        /// </summary>
        public bool IsHexString { get; set; } = false;

        public bool SkipForceConvert { get; internal set; } = false;

        public bool HexTrimLeadingZeroAsDefault { get; internal set; } = false;

        internal void CheckParams()
        {
            if (HashSizeInBits <= 0 || HashSizeInBits > 512)
                throw new ArgumentException("Wrong message digest length (d). It should be in the interval (0, 512].");
            if (ModeControl > 64)
                throw new ArgumentException("Wrong mode control (L). It should be in the interval (0, 64].");
            if (NumberOfRound < 1)
                throw new ArgumentException("Wrong number of rounds (r). It should be in the interval [1, +∞).");
        }

        internal TrimOptions GetTrimOptions()
        {
            return SkipForceConvert || HexTrimLeadingZeroAsDefault
                ? new() {SkipForceConvert = SkipForceConvert, HexTrimLeadingZeroAsDefault = HexTrimLeadingZeroAsDefault}
                : TrimOptions.Instance;
        }
    }
}