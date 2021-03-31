using System;
using System.Text;
using Cosmos.Security.Encryption.Core;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities.Encoders;
using Cosmos.Optionals;
using Cosmos.Text;

// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Encryption
{
    /// <summary>
    /// SM2 encryption provider.
    /// </summary>
    // ReSharper disable once InconsistentNaming
    public static partial class SM2EncryptionProvider
    {
        /// <summary>
        /// Encrypt by public key
        /// </summary>
        /// <param name="data"></param>
        /// <param name="publicKey"></param>
        /// <param name="encoding"></param>
        /// <param name="mode"></param>
        /// <returns></returns>
        public static string EncryptByPublicKey(string data, string publicKey, Encoding encoding = default, SM2Mode mode = SM2Mode.C1C3C2)
        {
            if (publicKey is null || publicKey.Length == 0)
                return null;

            if (data is null || data.Length == 0)
                return null;

            // ReSharper disable once ExpressionIsAlwaysNull
            encoding ??= encoding.SafeEncodingValue();

            return EncryptByPublicKey(encoding.GetBytes(data), publicKey, encoding, mode);
        }

        /// <summary>
        /// Encrypt by public key
        /// </summary>
        /// <param name="dataBytes"></param>
        /// <param name="publicKey"></param>
        /// <param name="encoding"></param>
        /// <param name="mode"></param>
        /// <returns></returns>
        public static string EncryptByPublicKey(byte[] dataBytes, string publicKey, Encoding encoding = default, SM2Mode mode = SM2Mode.C1C3C2)
        {
            if (publicKey is null || publicKey.Length == 0)
                return null;

            if (dataBytes is null || dataBytes.Length == 0)
                return null;

            // ReSharper disable once ExpressionIsAlwaysNull
            encoding ??= encoding.SafeEncodingValue();

            var publicKeyBytes = Hex.Decode(encoding.GetBytes(publicKey));

            var source = new byte[dataBytes.Length];
            Array.Copy(dataBytes, 0, source, 0, dataBytes.Length);

            var cipher = new SM2Core.Cipher();
            var sm2 = SM2Core.Instance;

            var userKey = sm2.ecc_curve.DecodePoint(publicKeyBytes);

            var c1 = cipher.Init_enc(sm2, userKey);
            cipher.Encrypt(source);

            var c3 = new byte[32];
            cipher.Dofinal(c3);

            var c1Str = encoding.GetString(Hex.Encode(c1.GetEncoded()));
            var c2Str = encoding.GetString(Hex.Encode(source));
            var c3Str = encoding.GetString(Hex.Encode(c3));

            return mode == SM2Mode.C1C2C3
                ? (c1Str + c2Str + c3Str).ToUpper()
                : (c1Str + c3Str + c2Str).ToUpper();
        }

        /// <summary>
        /// Encrypt by public key
        /// </summary>
        /// <param name="data"></param>
        /// <param name="publicKey"></param>
        /// <param name="encoding"></param>
        /// <param name="mode"></param>
        /// <returns></returns>
        public static byte[] EncryptByPublicKeyAsBytes(string data, string publicKey, Encoding encoding = default, SM2Mode mode = SM2Mode.C1C3C2)
        {
            if (publicKey is null || publicKey.Length == 0)
                return null;

            if (data is null || data.Length == 0)
                return null;

            // ReSharper disable once ExpressionIsAlwaysNull
            encoding ??= encoding.SafeEncodingValue();

            return encoding.GetBytes(EncryptByPublicKey(encoding.GetBytes(data), publicKey, encoding, mode));
        }

        /// <summary>
        /// Encrypt by public key
        /// </summary>
        /// <param name="dataBytes"></param>
        /// <param name="publicKey"></param>
        /// <param name="encoding"></param>
        /// <param name="mode"></param>
        /// <returns></returns>
        public static byte[] EncryptByPublicKeyAsBytes(byte[] dataBytes, string publicKey, Encoding encoding = default, SM2Mode mode = SM2Mode.C1C3C2)
        {
            if (publicKey is null || publicKey.Length == 0)
                return null;

            if (dataBytes is null || dataBytes.Length == 0)
                return null;

            // ReSharper disable once ExpressionIsAlwaysNull
            encoding ??= encoding.SafeEncodingValue();

            return encoding.GetBytes(EncryptByPublicKey(dataBytes, publicKey, encoding, mode));
        }

        /// <summary>
        /// Decrypt by private key
        /// </summary>
        /// <param name="data"></param>
        /// <param name="privateKey"></param>
        /// <param name="encoding"></param>
        /// <param name="mode"></param>
        /// <returns></returns>
        public static string DecryptByPrivateKey(string data, string privateKey, Encoding encoding = default, SM2Mode mode = SM2Mode.C1C3C2)
        {
            if (privateKey is null || privateKey.Length == 0)
                return null;

            if (data is null || data.Length == 0)
                return null;

            // ReSharper disable once ExpressionIsAlwaysNull
            encoding ??= encoding.SafeEncodingValue();

            return DecryptByPrivateKeyAsBytes(encoding.GetBytes(data), privateKey, encoding, mode).GetString(encoding);
        }

        /// <summary>
        /// Decrypt by private key
        /// </summary>
        /// <param name="dataBytes"></param>
        /// <param name="privateKey"></param>
        /// <param name="encoding"></param>
        /// <param name="mode"></param>
        /// <returns></returns>
        public static string DecryptByPrivateKey(byte[] dataBytes, string privateKey, Encoding encoding = default, SM2Mode mode = SM2Mode.C1C3C2)
        {
            if (privateKey is null || privateKey.Length == 0)
                return null;

            if (dataBytes is null || dataBytes.Length == 0)
                return null;

            // ReSharper disable once ExpressionIsAlwaysNull
            encoding ??= encoding.SafeEncodingValue();

            return DecryptByPrivateKeyAsBytes(dataBytes, privateKey, encoding, mode).GetString(encoding);
        }

        /// <summary>
        /// Decrypt by private key
        /// </summary>
        /// <param name="data"></param>
        /// <param name="privateKey"></param>
        /// <param name="encoding"></param>
        /// <param name="mode"></param>
        /// <returns></returns>
        public static byte[] DecryptByPrivateKeyAsBytes(string data, string privateKey, Encoding encoding = default, SM2Mode mode = SM2Mode.C1C3C2)
        {
            if (privateKey is null || privateKey.Length == 0)
                return null;

            if (data is null || data.Length == 0)
                return null;

            // ReSharper disable once ExpressionIsAlwaysNull
            encoding ??= encoding.SafeEncodingValue();

            return DecryptByPrivateKeyAsBytes(encoding.GetBytes(data), privateKey, encoding, mode);
        }

        /// <summary>
        /// Decrypt by private key
        /// </summary>
        /// <param name="dataBytes"></param>
        /// <param name="privateKey"></param>
        /// <param name="encoding"></param>
        /// <param name="mode"></param>
        /// <returns></returns>
        public static byte[] DecryptByPrivateKeyAsBytes(byte[] dataBytes, string privateKey, Encoding encoding = default, SM2Mode mode = SM2Mode.C1C3C2)
        {
            if (privateKey is null || privateKey.Length == 0)
                return null;

            if (dataBytes is null || dataBytes.Length == 0)
                return null;

            // ReSharper disable once ExpressionIsAlwaysNull
            encoding ??= encoding.SafeEncodingValue();

            var privateKeyBytes = Hex.Decode(encoding.GetBytes(privateKey));

            var (c1, c2, c3) = GetContent(dataBytes, mode, encoding);

            var sm2 = SM2Core.Instance;
            var userD = new BigInteger(1, privateKeyBytes);

            var c = sm2.ecc_curve.DecodePoint(c1);
            var cipher = new SM2Core.Cipher();
            cipher.Init_dec(userD, c);
            cipher.Decrypt(c2);
            cipher.Dofinal(c3);

            return c2;
        }

        private static (byte[] c1, byte[] c2, byte[] c3) GetContent(byte[] dataBytes, SM2Mode mode, Encoding encoding)
        {
            var data = dataBytes.GetString(encoding);
            var source = Hex.Decode(dataBytes);
            var c2Len = source.Length - 97;
            var c1Offset = 0;
            var c2Offset = mode == SM2Mode.C1C2C3 ? 130 : 130 + 64;
            var c3Offset = mode == SM2Mode.C1C2C3 ? 130 + 2 * c2Len : 130;

            var c1 = Hex.Decode(encoding.GetBytes(data.Substring(c1Offset, 130)));
            var c2 = Hex.Decode(encoding.GetBytes(data.Substring(c2Offset, 2 * c2Len)));
            var c3 = Hex.Decode(encoding.GetBytes(data.Substring(c3Offset, 64)));

            return (c1, c2, c3);
        }
    }
}