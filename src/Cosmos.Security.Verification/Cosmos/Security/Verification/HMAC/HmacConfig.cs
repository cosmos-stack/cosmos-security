using System;
using System.Security.Cryptography;

// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Verification
{
    public class HmacConfig
    {
        /// <summary>
        /// Length of the produced HMAC value, in bits.
        /// </summary>
        public int HashSizeInBits { get; internal set; }

        /// <summary>
        /// Type of HMAC
        /// </summary>
        public HmacTypes Type { get; internal set; }
        
        /// <summary>
        /// Internal HashAlgorithm Factory
        /// </summary>
        internal Func<KeyedHashAlgorithm> HashAlgorithmFactory { get; set; }
    }
}