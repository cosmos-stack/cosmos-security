using System;
using System.Text;
using Cosmos.Conversions;
using Cosmos.Optionals;

namespace Cosmos.Security.Cryptography
{
    public enum CipherTextTypes
    {
        PlainText,
        Base32Text,
        Base64Text,
        Base91Text,
        Base256Text,
        ZBase32Text,
        Hex,
        Custom
    }

    public static class CipherTextTypeExtensions
    {
        public static byte[] GetBytes(this CipherTextTypes signatureTextType, string signature, Encoding encoding = default, Func<string, byte[]> customCipherTextConverter = null)
        {
            encoding = encoding.SafeEncodingValue();

            return signatureTextType switch
            {
                CipherTextTypes.PlainText => encoding.GetBytes(signature),
                CipherTextTypes.Base32Text => BaseConv.FromBase32(signature),
                CipherTextTypes.Base64Text => BaseConv.FromBase64(signature),
                CipherTextTypes.Base91Text => BaseConv.FromBase91(signature),
                CipherTextTypes.Base256Text => BaseConv.FromBase256(signature),
                CipherTextTypes.ZBase32Text => BaseConv.FromZBase32(signature),
                CipherTextTypes.Hex => Org.BouncyCastle.Utilities.Encoders.Hex.Decode(signature),
                _ => customCipherTextConverter is null ? encoding.GetBytes(signature) : customCipherTextConverter(signature)
            };
        }
    }
}