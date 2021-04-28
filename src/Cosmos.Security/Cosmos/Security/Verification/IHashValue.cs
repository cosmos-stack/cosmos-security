using System;
using System.Collections;
using System.Text;

namespace Cosmos.Security.Verification
{
    public interface IHashValue : IEquatable<IHashValue>
    {
        int BitLength { get; }

        byte[] Hash { get; }

        BitArray GetBitArray();

        string GetHexString();

        string GetHexString(bool uppercase);

        string GetBinString();

        string GetBinString(bool complementZero);

        string GetBase64String();

        string GetString();

        string GetString(Encoding encoding);
    }
}