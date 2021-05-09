using System.Text;

namespace Cosmos.Security.Cryptography.Core
{
    internal class SignValue : ISignValue
    {
        public static Encoding DefaultEncoding = Encoding.UTF8;

        private readonly TrimOptions _options;

        public SignValue(byte[] signature, TrimOptions options)
        {
            Signature = signature;
            _options = options ?? TrimOptions.Instance;
        }

        public byte[] Signature { get; }

        public ICryptoValueDescriptor GetSignatureDescriptor()
        {
            return new CryptoValueDescriptor(Signature, Signature is not null, _options, DefaultEncoding);
        }
    }
}