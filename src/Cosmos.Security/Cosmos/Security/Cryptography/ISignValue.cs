namespace Cosmos.Security.Cryptography
{
    public interface ISignValue
    {
        byte[] Signature { get; }

        ICryptoValueDescriptor GetSignatureDescriptor();
    }
}