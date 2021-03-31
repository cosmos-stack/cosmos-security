using System;
using System.Collections;

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
    }
}