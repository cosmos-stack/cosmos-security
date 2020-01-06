using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Cosmos.Internals;

namespace Cosmos.Encryption.Core {
    /// <summary>
    /// Abstrace Symmetric/SymmetricEncryptionBase encryption.
    /// Reference: Seay Xu
    ///     https://github.com/godsharp/GodSharp.Encryption/blob/master/src/GodSharp.Shared/Encryption/Symmetric/XES.cs
    ///  Editor: AlexLEWIS
    /// </summary>
    // ReSharper disable once InconsistentNaming
    public abstract class SymmetricEncryptionBase {
        /// <summary>
        /// 用于整理获得真实 key / iv 的方法
        /// </summary>
        protected static Func<string, Func<string, Func<Encoding, Func<int, byte[]>>>>
            ComputeRealValueFunc() => originString => salt => encoding => size => {
            if (string.IsNullOrWhiteSpace(originString)) {
                return new byte[0];
            }

            encoding = EncodingHelper.Fixed(encoding);

            var len = size / 8;

            if (string.IsNullOrWhiteSpace(salt)) {
                var retBytes = new byte[len];
                Array.Copy(encoding.GetBytes(originString.PadRight(len)), retBytes, len);
                return retBytes;
            }

            var saltBytes = encoding.GetBytes(salt);
            var rfcOriginStringData = new Rfc2898DeriveBytes(encoding.GetBytes(originString), saltBytes, 1000);
            return rfcOriginStringData.GetBytes(len);
        };

        /// <summary>
        /// Nice encryption code
        /// </summary>
        /// <typeparam name="TCryptoServiceProvider"></typeparam>
        /// <param name="sourceBytes"></param>
        /// <param name="keyBytes"></param>
        /// <param name="ivBytes"></param>
        /// <returns></returns>
        protected static byte[] NiceEncryptCore<TCryptoServiceProvider>(byte[] sourceBytes, byte[] keyBytes, byte[] ivBytes)
            where TCryptoServiceProvider : SymmetricAlgorithm, new() {
            using (var provider = new TCryptoServiceProvider()) {
                provider.Key = keyBytes;
                provider.IV = ivBytes;
                using (MemoryStream ms = new MemoryStream()) {
                    using (CryptoStream cs = new CryptoStream(ms, provider.CreateEncryptor(), CryptoStreamMode.Write)) {
                        cs.Write(sourceBytes, 0, sourceBytes.Length);
                        cs.FlushFinalBlock();
                        return ms.ToArray();
                    }
                }
            }
        }

        /// <summary>
        /// Nice decryption core
        /// </summary>
        /// <typeparam name="TCryptoServiceProvider"></typeparam>
        /// <param name="encryptBytes"></param>
        /// <param name="keyBytes"></param>
        /// <param name="ivBytes"></param>
        /// <returns></returns>
        protected static byte[] NiceDecryptCore<TCryptoServiceProvider>(byte[] encryptBytes, byte[] keyBytes, byte[] ivBytes)
            where TCryptoServiceProvider : SymmetricAlgorithm, new() {
            using (var provider = new TCryptoServiceProvider()) {
                provider.Key = keyBytes;
                provider.IV = ivBytes;
                using (MemoryStream ms = new MemoryStream()) {
                    using (CryptoStream cs = new CryptoStream(ms, provider.CreateDecryptor(), CryptoStreamMode.Write)) {
                        cs.Write(encryptBytes, 0, encryptBytes.Length);
                        cs.FlushFinalBlock();
                        return ms.ToArray();
                    }
                }
            }
        }
    }
}