// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Verification
{
    public class Md6Options
    {
        /// <summary>
        /// Length of the produced Message Digest value, in bits.
        /// </summary>
        public int HashSizeInBits { get; set; }

        /// <summary>
        /// Mode control, [0, 64], be used for MD6
        /// </summary>
        public uint ModeControl { get; set; }

        /// <summary>
        /// Number of Round, be used for MD6 <br />
        /// default value: <br /> without key = 40 + d/4 <br /> with key = max(80, 40 + d/4)
        /// </summary>
        public uint NumberOfRound { get; set; }

        /// <summary>
        /// Key, be used for MD6
        /// </summary>
        public string Key { get; set; } = "";

        /// <summary>
        /// To flag the value of key is HEX string or not, be used for MD6
        /// </summary>
        public bool IsHexString { get; set; } = false;

        public static Md6Options Md6Bit128()
        {
            return new() {HashSizeInBits = 128, ModeControl = 64, NumberOfRound = 0};
        }

        public static Md6Options Md6Bit256()
        {
            return new() {HashSizeInBits = 256, ModeControl = 64, NumberOfRound = 0};
        }

        public static Md6Options Md6Bit512()
        {
            return new() {HashSizeInBits = 512, ModeControl = 64, NumberOfRound = 0};
        }

        public static implicit operator MdConfig(Md6Options options)
        {
            return new()
            {
                Type = MdTypes.Md6Custom,
                HashSizeInBits = options.HashSizeInBits,
                ModeControl = options.ModeControl,
                NumberOfRound = options.NumberOfRound,
                Key = options.Key,
                IsHexString = options.IsHexString,
                SkipForceConvert = true,
                HexTrimLeadingZeroAsDefault = true
            };
        }

        public static explicit operator Md6Options(MdConfig config)
        {
            return new()
            {
                HashSizeInBits = config.HashSizeInBits,
                ModeControl = config.ModeControl,
                NumberOfRound = config.NumberOfRound,
                Key = config.Key,
                IsHexString = config.IsHexString,
            };
        }
    }
}