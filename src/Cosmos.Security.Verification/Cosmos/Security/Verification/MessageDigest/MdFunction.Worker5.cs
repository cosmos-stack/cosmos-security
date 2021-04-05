using System;
using System.Security.Cryptography;
using System.Text;
using Cosmos.Conversions;

namespace Cosmos.Security.Verification.MessageDigest
{
    public partial class MdFunction
    {
        private class Md5Worker : IMessageDigestWorker
        {
            private readonly MdTypes _type;

            public Md5Worker(MdTypes type)
            {
                _type = type;
            }

            /// <summary>
            /// MD5 Worker
            /// </summary>
            /// <param name="buff"></param>
            /// <returns></returns>
            /// <exception cref="NotImplementedException"></exception>
            public byte[] Hash(ReadOnlySpan<byte> buff)
            {
                using var algorithm = MD5.Create();
                var hashVal = algorithm.ComputeHash(buff.ToArray());

                return _type switch
                {
                    MdTypes.Md5 => hashVal,
                    MdTypes.Md5Bit16 => hashVal.AsSpan(4, 8).ToArray(),
                    MdTypes.Md5Bit32 => hashVal,
                    MdTypes.Md5Bit64 => Encoding.UTF8.GetBytes(BaseConv.ToBase64(hashVal)),
                    _ => hashVal
                };
            }
        }
    }
}