using System;
using System.Text;
using Cosmos.Conversions;
using Cosmos.Optionals;

namespace Cosmos.Security.Cryptography.Core
{
    internal readonly struct CryptoValueDescriptor : ICryptoValueDescriptor
    {
        internal CryptoValueDescriptor(byte[] data, bool includeData, TrimOptions options, Encoding defaultEncoding)
        {
            _data = data;
            _includeData = includeData;
            Options = options;
            DefaultEncoding = defaultEncoding;
        }

        private byte[] _data { get; }

        public ReadOnlySpan<byte> Data => _data;

        private bool _includeData { get; }

        private TrimOptions Options { get; }

        public Encoding DefaultEncoding { get; }

        public bool IncludeData() => _includeData;

        public string GetString()
        {
            return GetString(DefaultEncoding);
        }

        public string GetString(Encoding encoding)
        {
            if (!IncludeData())
                return string.Empty;
            if (Options.TrimTerminatorWhenDecrypting)
                return encoding.SafeEncodingValue().GetString(_data).TrimEnd('\0');
            return encoding.SafeEncodingValue().GetString(_data);
        }

        public string GetHexString()
        {
            return GetHexString(false);
        }

        public string GetHexString(bool uppercase)
        {
            if (!IncludeData())
                return string.Empty;

            var stringBuilder = new StringBuilder(_data.Length);
            var formatString = uppercase ? "X2" : "x2";

            foreach (var byteValue in _data)
                stringBuilder.Append(byteValue.ToString(formatString));

            var result = stringBuilder.ToString();

            if (Options.HexTrimLeadingZeroAsDefault)
                result = result.TrimStart('0');

            return result;
        }

        public string GetBinString()
        {
            if (!IncludeData())
                return string.Empty;
            return ScaleConv.HexToBin(GetHexString());
        }

        public string GetBase64String()
        {
            if (!IncludeData())
                return string.Empty;
            return BaseConv.ToBase64(_data);
        }
    }
}