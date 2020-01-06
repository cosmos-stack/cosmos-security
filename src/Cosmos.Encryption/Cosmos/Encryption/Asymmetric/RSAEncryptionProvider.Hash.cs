using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Cosmos.Encryption.Core.Internals;
using Cosmos.Internals;

// ReSharper disable once CheckNamespace
namespace Cosmos.Encryption {
    /// <summary>
    /// Asymmetric/RSA encryption.
    /// Reference: Seay Xu
    ///     https://github.com/godsharp/GodSharp.Encryption/blob/master/src/GodSharp.Shared/Encryption/Asymmetric/RSA.cs
    /// Reference: myloveCc
    ///     https://github.com/myloveCc/NETCore.Encrypt/blob/master/src/NETCore.Encrypt/EncryptProvider.cs
    /// </summary>
    // ReSharper disable once InconsistentNaming
    public static partial class RSAEncryptionProvider {
        /// <summary>
        /// Get hash sign.
        /// </summary>
        /// <param name="data"></param>
        /// <param name="hashing"></param>
        /// <param name="encoding">The <see cref="T:System.Text.Encoding"/>,default is Encoding.UTF8.</param>
        /// <returns></returns>
        // ReSharper disable once RedundantAssignment
        public static bool GetHash(string data, ref byte[] hashing, Encoding encoding = null) {
            encoding = EncodingHelper.Fixed(encoding);
            hashing = HashStringFunc()(data)(encoding);
            return true;
        }

        /// <summary>
        /// Get hash sign.
        /// </summary>
        /// <param name="data"></param>
        /// <param name="hashing"></param>
        /// <param name="encoding">The <see cref="T:System.Text.Encoding"/>,default is Encoding.UTF8.</param>
        /// <returns></returns>
        // ReSharper disable once RedundantAssignment
        public static bool GetHash(string data, ref string hashing, Encoding encoding = null) {
            encoding = EncodingHelper.Fixed(encoding);
            hashing = Convert.ToBase64String(HashStringFunc()(data)(encoding));
            return true;
        }

        private static Func<string, Func<Encoding, byte[]>> HashStringFunc() =>
            data => encoding => HashAlgorithm.Create("MD5")?.ComputeHash(encoding.GetBytes(data));

        /// <summary>
        /// Get hash sign.
        /// </summary>
        /// <param name="fs"></param>
        /// <param name="hashing"></param>
        /// <returns></returns>
        // ReSharper disable once RedundantAssignment
        public static bool GetHash(FileStream fs, ref byte[] hashing) {
            hashing = HashFileFunc()(fs);
            return true;
        }

        /// <summary>
        /// Get hash sign.
        /// </summary>
        /// <param name="fs"></param>
        /// <param name="hashing"></param>
        /// <returns></returns>
        // ReSharper disable once RedundantAssignment
        public static bool GetHash(FileStream fs, ref string hashing) {
            hashing = Convert.ToBase64String(HashFileFunc()(fs));
            return true;
        }

        private static Func<FileStream, byte[]> HashFileFunc() => fs => {
            var ret = HashAlgorithm.Create("MD5")?.ComputeHash(fs);
            fs.Close();
            return ret;
        };
    }
}