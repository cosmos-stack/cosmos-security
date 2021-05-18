#if NETFRAMEWORK || NETSTANDARD2_0

using System.Diagnostics.CodeAnalysis;
using Cosmos.Security.Cryptography;

namespace System.Security.Cryptography
{
    /// <summary>
    /// Compatible extensions for RSA
    /// </summary>
    [SuppressMessage("ReSharper", "InconsistentNaming")]
    public static class RSACompatibleExtensions
    {
        /// <summary>
        /// Export RSA private key
        /// </summary>
        /// <param name="rsa"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static byte[] ExportRSAPrivateKey(this RSA rsa)
        {
            if (rsa is null)
                throw new ArgumentNullException(nameof(rsa));
            return Convert.FromBase64String(rsa.GetPrivateKeyInPkcs1());
        }

        /// <summary>
        /// Export RSA private key
        /// </summary>
        /// <param name="rsa"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static byte[] ExportPkcs8PrivateKey(this RSA rsa)
        {
            if (rsa is null)
                throw new ArgumentNullException(nameof(rsa));
            return Convert.FromBase64String(rsa.GetPrivateKeyInPkcs8());
        }

        /// <summary>
        /// Export RSA public key
        /// </summary>
        /// <param name="rsa"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static byte[] ExportRSAPublicKey(this RSA rsa)
        {
            if (rsa is null)
                throw new ArgumentNullException(nameof(rsa));
            return Convert.FromBase64String(rsa.GetPublicKeyInPkcs1());
        }

        /// <summary>
        /// Import RSA private key
        /// </summary>
        /// <param name="rsa"></param>
        /// <param name="privateKey"></param>
        /// <param name="bytesRead"></param>
        /// <exception cref="ArgumentNullException"></exception>
        public static void ImportRSAPrivateKey(this RSA rsa, ReadOnlySpan<byte> privateKey, out int bytesRead)
        {
            if (rsa is null)
                throw new ArgumentNullException(nameof(rsa));
            bytesRead = privateKey.Length;
            var key = Convert.ToBase64String(privateKey.ToArray());
            rsa.TouchFromPrivateKeyInPkcs1(key, out _);
        }

        /// <summary>
        /// Import pkcs8 RSA private key
        /// </summary>
        /// <param name="rsa"></param>
        /// <param name="privateKey"></param>
        /// <param name="bytesRead"></param>
        /// <exception cref="ArgumentNullException"></exception>
        public static void ImportPkcs8PrivateKey(this RSA rsa, ReadOnlySpan<byte> privateKey, out int bytesRead)
        {
            if (rsa is null)
                throw new ArgumentNullException(nameof(rsa));
            bytesRead = privateKey.Length;
            var key = Convert.ToBase64String(privateKey.ToArray());
            rsa.TouchFromPrivateKeyInPkcs8(key, out _);
        }

        /// <summary>
        /// Import RSA public key
        /// </summary>
        /// <param name="rsa"></param>
        /// <param name="publicKey"></param>
        /// <param name="bytesRead"></param>
        /// <exception cref="ArgumentNullException"></exception>
        public static void ImportRSAPublicKey(this RSA rsa, ReadOnlySpan<byte> publicKey, out int bytesRead)
        {
            if (rsa is null)
                throw new ArgumentNullException(nameof(rsa));
            bytesRead = publicKey.Length;
            var key = Convert.ToBase64String(publicKey.ToArray());
            rsa.TouchFromPublicKeyInPkcs1(key, out _);
        }
    }
}

#endif