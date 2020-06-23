using System;
using System.Security.Cryptography;
using System.Text;
using Cosmos.Encryption.Core.Internals.Extensions;
using Cosmos.Optionals;

// ReSharper disable once CheckNamespace
namespace Cosmos.Encryption
{
    /// <summary>
    /// Md5 hashing provider
    /// Reference: Seay Xu
    ///     https://github.com/godsharp/GodSharp.Encryption/blob/master/src/GodSharp.Shared/Encryption/Hash/MD5.cs
    /// Editor: AlexLEWIS
    /// </summary>
    // ReSharper disable once InconsistentNaming
    public static class MD5HashingProvider
    {
        /// <summary>
        /// MD5 hashing method, default encrypt string is 32 bits.
        /// </summary>
        /// <param name="data">The string you want to hash.</param>
        /// <param name="bits">Encrypt string bits number,only 16,32,64.</param>
        /// <param name="isUpper"></param>
        /// <param name="isIncludeHyphen"></param>
        /// <param name="encoding">The <see cref="T:System.Text.Encoding"/>,default is Encoding.UTF8.</param>
        /// <returns>Hashed string.</returns>
        public static string Signature(string data, MD5BitTypes bits = MD5BitTypes.L32, bool isUpper = true, bool isIncludeHyphen = false, Encoding encoding = null)
        {
            Checker.Data(data);

            encoding = encoding.SafeValue();

            return bits switch
            {
                MD5BitTypes.L16 => Encrypt16Func()(data)(encoding).ToFixUpperCase(isUpper).ToFixHyphenChar(isIncludeHyphen),
                MD5BitTypes.L32 => Encrypt32Func()(data)(encoding).ToFixUpperCase(isUpper).ToFixHyphenChar(isIncludeHyphen),
                MD5BitTypes.L64 => Encrypt64Func()(data)(encoding).ToFixUpperCase(isUpper).ToFixHyphenChar(isIncludeHyphen),
                _               => throw new ArgumentOutOfRangeException(nameof(bits), bits, null)
            };
        }

        private static Func<string, Func<Encoding, string>> Encrypt16Func() =>
            str => encoding => BitConverter.ToString(PreencryptFunc()(str)(encoding), 4, 8);

        private static Func<string, Func<Encoding, string>> Encrypt32Func() =>
            str => encoding => BitConverter.ToString(PreencryptFunc()(str)(encoding));

        private static Func<string, Func<Encoding, string>> Encrypt64Func() =>
            str => encoding => Convert.ToBase64String(PreencryptFunc()(str)(encoding));

        private static Func<string, Func<Encoding, byte[]>> PreencryptFunc() => str => encoding =>
        {
            using var md5 = MD5.Create();
            return md5.ComputeHash(encoding.GetBytes(str));
        };

        /// <summary>
        /// Verify 
        /// </summary>
        /// <param name="comparison"></param>
        /// <param name="data">The string of encrypt.</param>
        /// <param name="bits">Encrypt string bits number,only 16,32,64.</param>
        /// <param name="isUpper"></param>
        /// <param name="isIncludeHyphen"></param>
        /// <param name="encoding">The <see cref="T:System.Text.Encoding"/>,default is Encoding.UTF8.</param>
        /// <returns></returns>
        public static bool Verify(string comparison, string data, MD5BitTypes bits = MD5BitTypes.L32, bool isUpper = true, bool isIncludeHyphen = false, Encoding encoding = null)
            => comparison == Signature(data, bits, isUpper, isIncludeHyphen, encoding);
    }
}