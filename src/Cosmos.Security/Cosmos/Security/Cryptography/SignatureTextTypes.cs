using System;
using System.Text;
using Cosmos.Conversions;
using Cosmos.Optionals;
using Org.BouncyCastle.Utilities.Encoders;

namespace Cosmos.Security.Cryptography
{
    public enum SignatureTextTypes
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

    public static class SignatureTextTypeExtensions
    {
        public static byte[] GetBytes(this SignatureTextTypes signatureTextType, string signature, Encoding encoding = default, Func<string, byte[]> customSignatureTextConverter = null)
        {
            encoding = encoding.SafeEncodingValue();

            return signatureTextType switch
            {
                SignatureTextTypes.PlainText => encoding.GetBytes(signature),
                SignatureTextTypes.Base32Text => BaseConv.FromBase32(signature),
                SignatureTextTypes.Base64Text => BaseConv.FromBase64(signature),
                SignatureTextTypes.Base91Text => BaseConv.FromBase91(signature),
                SignatureTextTypes.Base256Text => BaseConv.FromBase256(signature),
                SignatureTextTypes.ZBase32Text => BaseConv.FromZBase32(signature),
                SignatureTextTypes.Hex => Hex.Decode(signature),
                _ => customSignatureTextConverter is null ? encoding.GetBytes(signature) : customSignatureTextConverter(signature)
            };
        }
    }
}