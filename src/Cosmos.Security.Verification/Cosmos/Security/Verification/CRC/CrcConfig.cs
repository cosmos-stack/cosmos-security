// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Verification
{
    /// <summary>
    /// CRC Hash Config
    /// </summary>
    public class CrcConfig
    {
        /// <summary>
        /// Length of the produced CRC value, in bits.
        /// </summary>
        public int HashSizeInBits { get; internal set; }

        /// <summary>
        /// Divisor to use when calculating the CRC.
        /// </summary>
        /// <value>
        /// The divisor that will be used when calculating the CRC value.
        /// </value>
        public ulong Polynomial { get; internal set; }

        /// <summary>
        /// Value to initialize the CRC register to before calculating the CRC.
        /// </summary>
        public ulong InitialValue { get; internal set; }

        /// <summary>
        /// If true, the CRC calculation processes input as big endian bit order.
        /// </summary>
        public bool ReflectIn { get; internal set; }

        /// <summary>
        /// If true, the CRC calculation processes the output as big endian bit order.
        /// </summary>
        public bool ReflectOut { get; internal set; }

        /// <summary>
        /// Value to xor with the final CRC value.
        /// </summary>
        public ulong XOrOut { get; internal set; }
    }
}