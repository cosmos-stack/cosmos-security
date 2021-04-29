using System;
using System.Text;

namespace Cosmos.Security.Cryptography
{
    public interface ICryptoValueDescriptor
    {
        ReadOnlySpan<byte> Data { get; }

        Encoding DefaultEncoding { get; }

        bool IncludeData();

        string GetString();

        string GetString(Encoding encoding);

        string GetHexString();

        string GetHexString(bool uppercase);

        string GetBinString();

        string GetBase64String();
    }
}