using System;
using System.Security.Cryptography;
using System.Text;

// ReSharper disable CheckNamespace
namespace Cosmos.Security.Cryptography
{
    public static class DesKeyGenerator
    {
        public static DesKey Generate(DesTypes type)
        {
            switch (type)
            {
                case DesTypes.DES:
                {
                    using var provider = new DESCryptoServiceProvider();
                    return new DesKey(DesTypes.DES, provider.Key, provider.IV);
                }

                case DesTypes.TripleDES128:
                {
                    using var provider = new TripleDESCryptoServiceProvider();
                    return new DesKey(DesTypes.TripleDES128, provider.Key, provider.IV);
                }

                case DesTypes.TripleDES192:
                {
                    using var provider = new TripleDESCryptoServiceProvider();
                    return new DesKey(DesTypes.TripleDES192, provider.Key, provider.IV);
                }

                default:
                    throw new ArgumentException("The length of the key is invalid.");
            }
        }

        public static DesKey Generate(DesTypes type, string pwd, string iv, Encoding encoding)
        {
            return type switch
            {
                DesTypes.DES => new DesKey(DesTypes.DES, pwd, iv, encoding),
                DesTypes.TripleDES128 => new DesKey(DesTypes.TripleDES128, pwd, iv, encoding),
                DesTypes.TripleDES192 => new DesKey(DesTypes.TripleDES192, pwd, iv, encoding),
                _ => throw new ArgumentException("The length of the key is invalid.")
            };
        }

        public static DesKey Generate(DesTypes type, byte[] pwd, byte[] iv)
        {
            return type switch
            {
                DesTypes.DES => new DesKey(DesTypes.DES, pwd, iv),
                DesTypes.TripleDES128 => new DesKey(DesTypes.TripleDES128, pwd, iv),
                DesTypes.TripleDES192 => new DesKey(DesTypes.TripleDES192, pwd, iv),
                _ => throw new ArgumentException("The length of the key is invalid.")
            };
        }
    }
}