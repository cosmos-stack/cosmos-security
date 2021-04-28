using Cosmos.Reflection;
using Cosmos.Security.Verification.Core;

namespace Cosmos.Security.Verification
{
    public static class HashCodeExtensions
    {
        public static IHashValue ToHashValue(this HashCode32 hash)
        {
            return new HashValue(hash.AsByteArray(), hash.HashSizeInBits);
        }

        public static IHashValue ToHashValue(this HashCode32? hash)
        {
            return hash.HasValue ? ToHashValue(hash.Value) : default;
        }
        
        public static IHashValue ToHashValue(this HashCode64 hash)
        {
            return new HashValue(hash.AsByteArray(), hash.HashSizeInBits);
        }

        public static IHashValue ToHashValue(this HashCode64? hash)
        {
            return hash.HasValue ? ToHashValue(hash.Value) : default;
        }
        
        public static IHashValue ToHashValue(this HashCode128 hash)
        {
            return new HashValue(hash.AsByteArray(), hash.HashSizeInBits);
        }

        public static IHashValue ToHashValue(this HashCode128? hash)
        {
            return hash.HasValue ? ToHashValue(hash.Value) : default;
        }
        
        public static IHashValue ToHashValue(this HashCode256 hash)
        {
            return new HashValue(hash.AsByteArray(), hash.HashSizeInBits);
        }

        public static IHashValue ToHashValue(this HashCode256? hash)
        {
            return hash.HasValue ? ToHashValue(hash.Value) : default;
        }
        
        public static IHashValue ToHashValue(this HashCode512 hash)
        {
            return new HashValue(hash.AsByteArray(), hash.HashSizeInBits);
        }

        public static IHashValue ToHashValue(this HashCode512? hash)
        {
            return hash.HasValue ? ToHashValue(hash.Value) : default;
        }
        
        public static IHashValue ToHashValue(this HashCode1024 hash)
        {
            return new HashValue(hash.AsByteArray(), hash.HashSizeInBits);
        }

        public static IHashValue ToHashValue(this HashCode1024? hash)
        {
            return hash.HasValue ? ToHashValue(hash.Value) : default;
        }
    }
}