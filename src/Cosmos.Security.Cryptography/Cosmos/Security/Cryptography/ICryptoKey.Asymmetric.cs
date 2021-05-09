namespace Cosmos.Security.Cryptography
{
    public interface IAsymmetricCryptoKey : ICryptoKey
    {
        AsymmetricKeyMode Mode { get; }

        string PublicKey { get; }

        string PrivateKey { get; }

        bool IncludePublicKey();

        bool IncludePrivateKey();

        int Size { get; }
    }
}