using System.Collections.Generic;

namespace Cosmos.Security.Cryptography
{
    public interface ICryptoValue
    {
        byte[] OriginalData { get; }

        byte[] CipherData { get; }

        bool IncludeOriginalData();

        bool IncludeCipherData();

        IReadOnlyDictionary<string, object> ContextData { get; }

        ICryptoValueDescriptor GetOriginalDataDescriptor();

        ICryptoValueDescriptor GetCipherDataDescriptor();
    }
}