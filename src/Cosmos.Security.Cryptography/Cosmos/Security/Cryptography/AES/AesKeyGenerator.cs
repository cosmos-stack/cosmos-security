using System;
using System.Security.Cryptography;
using System.Text;

// ReSharper disable CheckNamespace

namespace Cosmos.Security.Cryptography
{
    public static class AesKeyGenerator
    {
        public static AesKey Generate(AesTypes type)
        {
            switch (type)
            {
                case AesTypes.Aes128:
                {
                    using var provider = new AesCryptoServiceProvider {KeySize = (int) type};
                    return new AesKey(AesTypes.Aes128, provider.Key, provider.IV);
                }

                case AesTypes.Aes192:
                {
                    using var provider = new AesCryptoServiceProvider {KeySize = (int) type};
                    return new AesKey(AesTypes.Aes192, provider.Key, provider.IV);
                }

                case AesTypes.Aes256:
                {
                    using var provider = new AesCryptoServiceProvider {KeySize = (int) type};
                    return new AesKey(AesTypes.Aes256, provider.Key, provider.IV);
                }

                default:
                    throw new ArgumentException("The length of the key is invalid.");
            }
        }

        public static AesKey Generate(AesTypes type, string pwd, string iv, Encoding encoding)
        {
            return type switch
            {
                AesTypes.Aes128 => new AesKey(AesTypes.Aes128, pwd, iv, encoding),
                AesTypes.Aes192 => new AesKey(AesTypes.Aes192, pwd, iv, encoding),
                AesTypes.Aes256 => new AesKey(AesTypes.Aes256, pwd, iv, encoding),
                _ => throw new ArgumentException("The length of the key is invalid.")
            };
        }

        public static AesKey Generate(AesTypes type, byte[] pwd, byte[] iv)
        {
            return type switch
            {
                AesTypes.Aes128 => new AesKey(AesTypes.Aes128, pwd, iv),
                AesTypes.Aes192 => new AesKey(AesTypes.Aes192, pwd, iv),
                AesTypes.Aes256 => new AesKey(AesTypes.Aes256, pwd, iv),
                _ => throw new ArgumentException("The length of the key is invalid.")
            };
        }
    }
}