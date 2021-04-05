namespace Cosmos.Security.Verification.MessageDigest
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
    }
}