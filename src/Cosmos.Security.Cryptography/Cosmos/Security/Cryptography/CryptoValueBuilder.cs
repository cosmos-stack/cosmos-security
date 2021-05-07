using System;
using System.Collections.Generic;
using System.Text;
using Cosmos.Optionals;
using Cosmos.Security.Cryptography.Core;

namespace Cosmos.Security.Cryptography
{
    public class CryptoValueBuilder
    {
        private CryptoValueBuilder(Encoding encoding)
        {
            _cachedString = new string[2];
            _cachedBytes = new byte[2][];
            _encoding = encoding.SafeEncodingValue();
            _flags = new bool?[2];
            _cryptoContextData = new Dictionary<string, object>();
            _options = TrimOptions.Instance;
        }

        private Encoding _encoding;
        private string[] _cachedString;
        private byte[][] _cachedBytes;
        private bool?[] _flags;
        private CryptoMode _processingDirection;
        private Dictionary<string, object> _cryptoContextData;
        private TrimOptions _options;

        public CryptoValueBuilder OriginalTextIs(string originalText)
        {
            _cachedString[0] = originalText;
            _flags[0] = false;
            return this;
        }

        public CryptoValueBuilder OriginalTextIs(byte[] originalTextBytes)
        {
            _cachedBytes[0] = originalTextBytes;
            _flags[0] = true;
            return this;
        }

        public CryptoValueBuilder CipherTextIs(string cipherText)
        {
            _cachedString[1] = cipherText;
            _flags[1] = false;
            return this;
        }

        public CryptoValueBuilder CipherTextIs(byte[] cipherTextBytes)
        {
            _cachedBytes[1] = cipherTextBytes;
            _flags[1] = true;
            return this;
        }

        public CryptoValueBuilder ProcessingDirection(CryptoMode mode)
        {
            _processingDirection = mode;
            return this;
        }

        public CryptoValueBuilder AppendData(string dataKey, object data)
        {
            _cryptoContextData[dataKey] = data;
            return this;
        }

        internal CryptoValueBuilder Configure(Action<TrimOptions> optionsAct)
        {
            optionsAct?.Invoke(_options);
            return this;
        }

        public ICryptoValue Build()
        {
            var original = _flags[0].HasValue
                ? _flags[0].Value
                    ? _cachedBytes[0]
                    : _encoding.GetBytes(_cachedString[0])
                : throw new ArgumentException("No original text is set.");

            var cipher = _flags[1].HasValue
                ? _flags[1].Value
                    ? _cachedBytes[1]
                    : _encoding.GetBytes(_cachedString[1])
                : throw new ArgumentException("No cipher text is set.");

            return new CryptoValue(original, cipher, _processingDirection, _cryptoContextData, _options);
        }

        public static CryptoValueBuilder Create() => new(CryptoValue.DefaultEncoding);

        public static CryptoValueBuilder Create(Encoding encoding) => new(encoding);
    }
}