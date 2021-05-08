using System;
using System.Text;
using Cosmos.Optionals;
using Factory = Cosmos.Security.Cryptography.Sm4Factory;

// ReSharper disable InconsistentNaming

namespace Cosmos.Security.Cryptography
{
    public static class SM4
    {
        public static Sm4Key GenerateKey(Sm4Types type = Sm4Types.ECB) => Factory.GenerateKey(type);

        public static Sm4Key GenerateKey(Sm4Types type, int length) => Factory.GenerateKey(type, length);

        public static Sm4Key GenerateKey(string pwd, Encoding encoding = null) => Factory.GenerateKey(pwd, encoding);

        public static Sm4Key GenerateKey(string pwd, string iv, Encoding encoding = null) => Factory.GenerateKey(pwd, iv, encoding);

        public static Sm4Key GenerateKey(byte[] pwd) => Factory.GenerateKey(pwd);

        public static Sm4Key GenerateKey(byte[] pwd, byte[] iv) => Factory.GenerateKey(pwd, iv);

        public static ISM4 Create(Sm4Types type = Sm4Types.ECB) => Factory.Create(type);

        public static ISM4 Create(Sm4Types type, string pwd, Encoding encoding = null) => Factory.Create(type, pwd, encoding);

        public static ISM4 Create(Sm4Types type, string pwd, string iv, Encoding encoding = null) => Factory.Create(type, pwd, iv, encoding);

        public static ISM4 Create(Sm4Types type, byte[] pwd) => Factory.Create(type, pwd);

        public static ISM4 Create(Sm4Types type, byte[] pwd, byte[] iv) => Factory.Create(type, pwd, iv);

        public static ISM4 Create(Sm4Types type, Sm4Key key) => Factory.Create(type, key);

        public static ICryptoValue Encrypt(string originalText, string pwd, Encoding encoding = null)
        {
            encoding = encoding.SafeEncodingValue();
            var key = Factory.GenerateKey(pwd, encoding);
            var function = Factory.Create(Sm4Types.ECB, key);
            return function.Encrypt(originalText, encoding);
        }

        public static ICryptoValue Encrypt(Sm4Types type, string originalText, string pwd, Encoding encoding = null)
        {
            encoding = encoding.SafeEncodingValue();
            var key = Factory.GenerateKey(pwd, encoding);
            var function = Factory.Create(type, key);
            return function.Encrypt(originalText, encoding);
        }

        public static ICryptoValue Encrypt(byte[] originalBytes, byte[] pwd)
        {
            var key = Factory.GenerateKey(pwd);
            var function = Factory.Create(Sm4Types.ECB, key);
            return function.Encrypt(originalBytes);
        }

        public static ICryptoValue Encrypt(Sm4Types type, byte[] originalBytes, byte[] pwd)
        {
            var key = Factory.GenerateKey(pwd);
            var function = Factory.Create(type, key);
            return function.Encrypt(originalBytes);
        }

        public static ICryptoValue Decrypt(string cipherText, string pwd, Encoding encoding = null)
        {
            encoding = encoding.SafeEncodingValue();
            var key = Factory.GenerateKey(pwd, encoding);
            var function = Factory.Create(Sm4Types.ECB, key);
            return function.Decrypt(cipherText, encoding);
        }

        public static ICryptoValue Decrypt(Sm4Types type, string cipherText, string pwd, Encoding encoding = null)
        {
            encoding = encoding.SafeEncodingValue();
            var key = Factory.GenerateKey(pwd, encoding);
            var function = Factory.Create(type, key);
            return function.Decrypt(cipherText, encoding);
        }

        public static ICryptoValue Decrypt(string cipherText, string pwd, CipherTextTypes cipherTextType, Encoding encoding = null, Func<string, byte[]> customConverter = null)
        {
            encoding = encoding.SafeEncodingValue();
            var key = Factory.GenerateKey(pwd, encoding);
            var function = Factory.Create(Sm4Types.ECB, key);
            return function.Decrypt(cipherText, cipherTextType, encoding, customConverter);
        }

        public static ICryptoValue Decrypt(Sm4Types type, string cipherText, string pwd, CipherTextTypes cipherTextType, Encoding encoding = null, Func<string, byte[]> customConverter = null)
        {
            encoding = encoding.SafeEncodingValue();
            var key = Factory.GenerateKey(pwd, encoding);
            var function = Factory.Create(type, key);
            return function.Decrypt(cipherText, cipherTextType, encoding, customConverter);
        }

        public static ICryptoValue Decrypt(byte[] cipherBytes, byte[] pwd)
        {
            var key = Factory.GenerateKey(pwd);
            var function = Factory.Create(Sm4Types.ECB, key);
            return function.Decrypt(cipherBytes);
        }

        public static ICryptoValue Decrypt(Sm4Types type, byte[] cipherBytes, byte[] pwd)
        {
            var key = Factory.GenerateKey(pwd);
            var function = Factory.Create(type, key);
            return function.Decrypt(cipherBytes);
        }
    }
}