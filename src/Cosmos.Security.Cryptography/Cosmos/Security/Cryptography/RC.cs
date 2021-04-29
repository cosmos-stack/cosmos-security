using System;
using System.Text;
using Cosmos.Optionals;
using Factory = Cosmos.Security.Cryptography.RcFactory;

// ReSharper disable InconsistentNaming

namespace Cosmos.Security.Cryptography
{
    public static class RC
    {
        public static RcKey GenerateKey(RcTypes type = RcTypes.RC4) => Factory.GenerateKey(type);

        public static RcKey GenerateKey(RcTypes type, string pwd, Encoding encoding) => Factory.GenerateKey(type, pwd, encoding);

        public static RcKey GenerateKey(RcTypes type, byte[] pwd) => Factory.GenerateKey(type, pwd);

        public static IRC Create() => new RC4Function(GenerateKey());

        public static IRC Create(RcTypes type) => Factory.Create(type);

        public static IRC Create(RcTypes type, string pwd, Encoding encoding = null) => Factory.Create(type, pwd, encoding);

        public static IRC Create(RcTypes type, byte[] pwd) => Factory.Create(type, pwd);

        public static IRC Create(RcTypes type, RcKey key) => Factory.Create(type, key);

        public static ICryptoValue Encrypt(string originalText, string pwd, Encoding encoding = null)
        {
            encoding = encoding.SafeEncodingValue();
            var key = Factory.GenerateKey(RcTypes.RC4, pwd, encoding);
            var function = Factory.Create(RcTypes.RC4, key);
            return function.Encrypt(originalText, encoding);
        }

        public static ICryptoValue Encrypt(RcTypes type, string originalText, string pwd, Encoding encoding = null)
        {
            encoding = encoding.SafeEncodingValue();
            var key = Factory.GenerateKey(type, pwd, encoding);
            var function = Factory.Create(type, key);
            return function.Encrypt(originalText, encoding);
        }

        public static ICryptoValue Encrypt(byte[] originalBytes, byte[] pwd)
        {
            var key = Factory.GenerateKey(RcTypes.RC4, pwd);
            var function = Factory.Create(RcTypes.RC4, key);
            return function.Encrypt(originalBytes);
        }

        public static ICryptoValue Encrypt(RcTypes type, byte[] originalBytes, byte[] pwd)
        {
            var key = Factory.GenerateKey(type, pwd);
            var function = Factory.Create(type, key);
            return function.Encrypt(originalBytes);
        }

        public static ICryptoValue Decrypt(string cipherText, string pwd, Encoding encoding = null)
        {
            encoding = encoding.SafeEncodingValue();
            var key = Factory.GenerateKey(RcTypes.RC4, pwd, encoding);
            var function = Factory.Create(RcTypes.RC4, key);
            return function.Decrypt(cipherText, encoding);
        }

        public static ICryptoValue Decrypt(RcTypes type, string cipherText, string pwd, Encoding encoding = null)
        {
            encoding = encoding.SafeEncodingValue();
            var key = Factory.GenerateKey(type, pwd, encoding);
            var function = Factory.Create(type, key);
            return function.Decrypt(cipherText, encoding);
        }

        public static ICryptoValue Decrypt(string cipherText, string pwd, CipherTextTypes cipherTextType, Encoding encoding = null, Func<string, byte[]> customConverter = null)
        {
            encoding = encoding.SafeEncodingValue();
            var key = Factory.GenerateKey(RcTypes.RC4, pwd, encoding);
            var function = Factory.Create(RcTypes.RC4, key);
            return function.Decrypt(cipherText, cipherTextType, encoding, customConverter);
        }

        public static ICryptoValue Decrypt(RcTypes type, string cipherText, string pwd, CipherTextTypes cipherTextType, Encoding encoding = null, Func<string, byte[]> customConverter = null)
        {
            encoding = encoding.SafeEncodingValue();
            var key = Factory.GenerateKey(type, pwd, encoding);
            var function = Factory.Create(type, key);
            return function.Decrypt(cipherText, cipherTextType, encoding, customConverter);
        }

        public static ICryptoValue Decrypt(byte[] cipherBytes, byte[] pwd)
        {
            var key = Factory.GenerateKey(RcTypes.RC4, pwd);
            var function = Factory.Create(RcTypes.RC4, key);
            return function.Decrypt(cipherBytes);
        }

        public static ICryptoValue Decrypt(RcTypes type, byte[] cipherBytes, byte[] pwd)
        {
            var key = Factory.GenerateKey(type, pwd);
            var function = Factory.Create(type, key);
            return function.Decrypt(cipherBytes);
        }
    }
}