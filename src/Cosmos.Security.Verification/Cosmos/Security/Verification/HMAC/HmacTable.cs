using System;
using System.Security.Cryptography;

// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Verification
{
    internal static class HmacTable
    {
        private static (int, Func<KeyedHashAlgorithm>) Dict(HmacTypes type)
        {
            return type switch
            {
                HmacTypes.HmacMd5 => (128, () => new HMACMD5()),
                HmacTypes.HmacSha1 => (160, () => new HMACSHA1()),
                HmacTypes.HmacSha256 => (256, () => new HMACSHA256()),
                HmacTypes.HmacSha384 => (384, () => new HMACSHA384()),
                HmacTypes.HmacSha512 => (512, () => new HMACSHA512()),
                _ => throw new ArgumentOutOfRangeException(nameof(type), type, null)
            };
        }

        public static HmacConfig Map(HmacTypes type)
        {
            var (hashSize, factory) = Dict(type);

            return new()
            {
                Type = type,
                HashSizeInBits = hashSize,
                HashAlgorithmFactory = factory
            };
        }
    }
}