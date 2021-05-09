using System;
using System.Security.Cryptography;

// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Cryptography
{
    public static class DsaKeyGenerator
    {
        public static DsaKey CreateKey(AsymmetricKeyMode mode, int keySize = 1024)
        {
            using var provider = new DSACryptoServiceProvider(keySize);

            switch (mode)
            {
                case AsymmetricKeyMode.PublicKey:
                    return DsaKey.CreateFromPublicKey(provider.ToXmlString(false), provider.KeySize);

                case AsymmetricKeyMode.PrivateKey:
                    return DsaKey.CreateFromPrivateKey(provider.ToXmlString(true), provider.KeySize);

                case AsymmetricKeyMode.Both:
                    return DsaKey.Create(
                        provider.ToXmlString(true),
                        provider.ToXmlString(false),
                        provider.KeySize);

                default:
                    throw new ArgumentOutOfRangeException(nameof(mode), mode, null);
            }
        }

        public static DsaKey FromPublicKeyInXml(string xmlPublicKey)
        {
            using var provider = new DSACryptoServiceProvider();

            provider.FromXmlString(xmlPublicKey);

            return DsaKey.CreateFromPublicKey(provider.ToXmlString(false), provider.KeySize);
        }

        public static DsaKey FromPrivateKeyInXml(string xmlPrivateKey)
        {
            using var provider = new DSACryptoServiceProvider();

            provider.FromXmlString(xmlPrivateKey);

            return DsaKey.CreateFromPrivateKey(provider.ToXmlString(true), provider.KeySize);
        }
    }
}