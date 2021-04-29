using System;
using System.Collections.Generic;
using System.Text;
using Cosmos.Collections;
using Cosmos.Conversions;
using Cosmos.Optionals;

namespace Cosmos.Security.Cryptography.Core
{
    internal class CryptoValue : ICryptoValue
    {
        public static Encoding DefaultEncoding = Encoding.UTF8;

        private readonly TrimOptions _options;

        public CryptoValue(
            byte[] original,
            byte[] cipher,
            CryptoMode direction,
            Dictionary<string, object> contextData, TrimOptions options)
        {
            OriginalData = original;
            CipherData = cipher;
            Direction = direction;
            CryptoContextData = contextData ?? new Dictionary<string, object>();

            _options = options ?? TrimOptions.Instance;
        }

        public byte[] OriginalData { get; }

        public byte[] CipherData { get; }

        public bool IncludeOriginalData() => OriginalData is not null;

        public bool IncludeCipherData() => CipherData is not null;

        public Dictionary<string, object> CryptoContextData { get; set; }

        public CryptoMode Direction { get; }

        public IReadOnlyDictionary<string, object> ContextData => CryptoContextData.AsReadOnlyDictionary();

        public ICryptoValueDescriptor GetOriginalDataDescriptor() => new CryptoValueDescriptor(OriginalData, IncludeOriginalData(), _options, DefaultEncoding);

        public ICryptoValueDescriptor GetCipherDataDescriptor() => new CryptoValueDescriptor(CipherData, IncludeCipherData(), _options, DefaultEncoding);
    }
}