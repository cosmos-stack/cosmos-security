using System.Collections.Generic;

namespace Cosmos.Security.Cryptography.Core
{
    internal class SignableCryptoValue : CryptoValue, ISignableCryptoValue
    {
        public SignableCryptoValue(byte[] original, byte[] cipher, CryptoMode direction, Dictionary<string, object> contextData, TrimOptions options)
            : base(original, cipher, direction, contextData, options) { }
    }
}