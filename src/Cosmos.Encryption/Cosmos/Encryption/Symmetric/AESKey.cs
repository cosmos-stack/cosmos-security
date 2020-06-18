// ReSharper disable once CheckNamespace

namespace Cosmos.Encryption
{
    /// <summary>
    /// Aes key
    /// </summary>
    // ReSharper disable once InconsistentNaming
    public class AESKey
    {
        /// <summary>
        /// Aes key
        /// </summary>
        public string Key { get; set; }

        /// <summary>
        /// Aes IV
        /// </summary>
        // ReSharper disable once InconsistentNaming
        public string IV { get; set; }

        /// <summary>
        /// Key size
        /// </summary>
        public AESKeySizeTypes Size { get; set; }
    }
}