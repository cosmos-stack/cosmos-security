// ReSharper disable once CheckNamespace

namespace Cosmos.Encryption
{
    /// <summary>
    /// Triple des key
    /// </summary>
    // ReSharper disable once InconsistentNaming
    public class TripleDESKey
    {
        /// <summary>
        /// Des key
        /// </summary>
        public string Key { get; set; }

        /// <summary>
        /// Des IV
        /// </summary>
        // ReSharper disable once InconsistentNaming
        public string IV { get; set; }
    }
}