using System;
using System.Text;
using Cosmos.Optionals;
using Factory = Cosmos.Security.Cryptography.AesFactory;

// ReSharper disable InconsistentNaming

namespace Cosmos.Security.Cryptography
{
    public static class AES
    {
        public static AesKey GenerateKey(AesTypes type = AesTypes.Aes256) => Factory.GenerateKey(type);

        public static AesKey GenerateKey(AesTypes type, string pwd, string iv, Encoding encoding) => Factory.GenerateKey(type, pwd, iv, encoding);

        public static AesKey GenerateKey(AesTypes type, byte[] pwd, byte[] iv) => Factory.GenerateKey(type, pwd, iv);

        public static IAES Create() => Factory.Create();

        public static IAES Create(AesTypes type) => Factory.Create(type);

        public static IAES Create(AesTypes type, string pwd, string iv, Encoding encoding = null) => Factory.Create(type, pwd, iv, encoding);

        public static IAES Create(AesTypes type, byte[] pwd, byte[] iv) => Factory.Create(type, pwd, iv);

        public static IAES Create(AesTypes type, AesKey key) => Factory.Create(type, key);

        public static ICryptoValue Encrypt(string originalText, string pwd, string iv, Encoding encoding = null)
        {
            encoding = encoding.SafeEncodingValue();
            var key = Factory.GenerateKey(AesTypes.Aes256, pwd, iv, encoding);
            var function = Factory.Create(AesTypes.Aes256, key);
            return function.Encrypt(originalText, encoding);
        }

        public static ICryptoValue Encrypt(AesTypes type, string originalText, string pwd, string iv, Encoding encoding = null)
        {
            encoding = encoding.SafeEncodingValue();
            var key = Factory.GenerateKey(type, pwd, iv, encoding);
            var function = Factory.Create(type, key);
            return function.Encrypt(originalText, encoding);
        }

        public static ICryptoValue Encrypt(string originalText, string pwd, string iv, string salt, Encoding encoding = null)
        {
            encoding = encoding.SafeEncodingValue();
            var key = Factory.GenerateKey(AesTypes.Aes256, pwd, iv, encoding);
            var function = Factory.Create(AesTypes.Aes256, key);
            return function.Encrypt(originalText, salt, encoding);
        }

        public static ICryptoValue Encrypt(AesTypes type, string originalText, string pwd, string iv, string salt, Encoding encoding = null)
        {
            encoding = encoding.SafeEncodingValue();
            var key = Factory.GenerateKey(type, pwd, iv, encoding);
            var function = Factory.Create(type, key);
            return function.Encrypt(originalText, salt, encoding);
        }

        public static ICryptoValue Encrypt(byte[] originalBytes, byte[] pwd, byte[] iv)
        {
            var key = Factory.GenerateKey(AesTypes.Aes256, pwd, iv);
            var function = Factory.Create(AesTypes.Aes256, key);
            return function.Encrypt(originalBytes);
        }

        public static ICryptoValue Encrypt(AesTypes type, byte[] originalBytes, byte[] pwd, byte[] iv)
        {
            var key = Factory.GenerateKey(type, pwd, iv);
            var function = Factory.Create(type, key);
            return function.Encrypt(originalBytes);
        }

        public static ICryptoValue Encrypt(byte[] originalBytes, byte[] pwd, byte[] iv, byte[] salt)
        {
            var key = Factory.GenerateKey(AesTypes.Aes256, pwd, iv);
            var function = Factory.Create(AesTypes.Aes256, key);
            return function.Encrypt(originalBytes, salt);
        }

        public static ICryptoValue Encrypt(AesTypes type, byte[] originalBytes, byte[] pwd, byte[] iv, byte[] salt)
        {
            var key = Factory.GenerateKey(type, pwd, iv);
            var function = Factory.Create(type, key);
            return function.Encrypt(originalBytes, salt);
        }

        public static ICryptoValue Decrypt(string cipherText, string pwd, string iv, Encoding encoding = null)
        {
            encoding = encoding.SafeEncodingValue();
            var key = Factory.GenerateKey(AesTypes.Aes256, pwd, iv, encoding);
            var function = Factory.Create(AesTypes.Aes256, key);
            return function.Decrypt(cipherText, encoding);
        }

        public static ICryptoValue Decrypt(AesTypes type, string cipherText, string pwd, string iv, Encoding encoding = null)
        {
            encoding = encoding.SafeEncodingValue();
            var key = Factory.GenerateKey(type, pwd, iv, encoding);
            var function = Factory.Create(type, key);
            return function.Decrypt(cipherText, encoding);
        }

        public static ICryptoValue Decrypt(string cipherText, string pwd, string iv, string salt, Encoding encoding = null)
        {
            encoding = encoding.SafeEncodingValue();
            var key = Factory.GenerateKey(AesTypes.Aes256, pwd, iv, encoding);
            var function = Factory.Create(AesTypes.Aes256, key);
            return function.Decrypt(cipherText, salt, encoding);
        }

        public static ICryptoValue Decrypt(AesTypes type, string cipherText, string pwd, string iv, string salt, Encoding encoding = null)
        {
            encoding = encoding.SafeEncodingValue();
            var key = Factory.GenerateKey(type, pwd, iv, encoding);
            var function = Factory.Create(type, key);
            return function.Decrypt(cipherText, salt, encoding);
        }

        public static ICryptoValue Decrypt(string cipherText, string pwd, string iv, CipherTextTypes cipherTextType, Encoding encoding = null, Func<string, byte[]> customConverter = null)
        {
            encoding = encoding.SafeEncodingValue();
            var key = Factory.GenerateKey(AesTypes.Aes256, pwd, iv, encoding);
            var function = Factory.Create(AesTypes.Aes256, key);
            return function.Decrypt(cipherText, cipherTextType, encoding, customConverter);
        }

        public static ICryptoValue Decrypt(AesTypes type, string cipherText, string pwd, string iv, CipherTextTypes cipherTextType, Encoding encoding = null, Func<string, byte[]> customConverter = null)
        {
            encoding = encoding.SafeEncodingValue();
            var key = Factory.GenerateKey(type, pwd, iv, encoding);
            var function = Factory.Create(type, key);
            return function.Decrypt(cipherText, cipherTextType, encoding, customConverter);
        }

        public static ICryptoValue Decrypt(string cipherText, string pwd, string iv, string salt, CipherTextTypes cipherTextType, Encoding encoding = null, Func<string, byte[]> customConverter = null)
        {
            encoding = encoding.SafeEncodingValue();
            var key = Factory.GenerateKey(AesTypes.Aes256, pwd, iv, encoding);
            var function = Factory.Create(AesTypes.Aes256, key);
            return function.Decrypt(cipherText, salt, cipherTextType, encoding, customConverter);
        }

        public static ICryptoValue Decrypt(AesTypes type, string cipherText, string pwd, string iv, string salt, CipherTextTypes cipherTextType, Encoding encoding = null, Func<string, byte[]> customConverter = null)
        {
            encoding = encoding.SafeEncodingValue();
            var key = Factory.GenerateKey(type, pwd, iv, encoding);
            var function = Factory.Create(type, key);
            return function.Decrypt(cipherText, salt, cipherTextType, encoding, customConverter);
        }

        public static ICryptoValue Decrypt(byte[] cipherBytes, byte[] pwd, byte[] iv)
        {
            var key = Factory.GenerateKey(AesTypes.Aes256, pwd, iv);
            var function = Factory.Create(AesTypes.Aes256, key);
            return function.Decrypt(cipherBytes);
        }

        public static ICryptoValue Decrypt(AesTypes type, byte[] cipherBytes, byte[] pwd, byte[] iv)
        {
            var key = Factory.GenerateKey(type, pwd, iv);
            var function = Factory.Create(type, key);
            return function.Decrypt(cipherBytes);
        }

        public static ICryptoValue Decrypt(byte[] cipherBytes, byte[] pwd, byte[] iv, byte[] salt)
        {
            var key = Factory.GenerateKey(AesTypes.Aes256, pwd, iv);
            var function = Factory.Create(AesTypes.Aes256, key);
            return function.Decrypt(cipherBytes, salt);
        }

        public static ICryptoValue Decrypt(AesTypes type, byte[] cipherBytes, byte[] pwd, byte[] iv, byte[] salt)
        {
            var key = Factory.GenerateKey(type, pwd, iv);
            var function = Factory.Create(type, key);
            return function.Decrypt(cipherBytes, salt);
        }
    }
}