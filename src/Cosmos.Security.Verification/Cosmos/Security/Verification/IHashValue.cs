using System;
using System.Collections;
using System.Text;

namespace Cosmos.Security.Verification
{
    public interface IHashValue : IEquatable<IHashValue>
    {
        int BitLength { get; }

        byte[] Hash { get; }

        BitArray AsBitArray();

        string AsHexString();

        string AsHexString(bool uppercase);

        string AsBinString();

        string AsBinString(bool complementZero);

        string AsBase64String();

        string AsString();

        string AsString(Encoding encoding);
    }
}