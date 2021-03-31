namespace Cosmos.Security.Encryption.Abstractions
{
    /// <summary>
    /// Interface for encryption algorithm
    /// </summary>
    public interface IEncryptionAlgorithm
    {
        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="plainText"></param>
        /// <returns></returns>
        string Encrypt(string plainText);

        /// <summary>
        /// Decrypt
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns></returns>
        string Decrypt(string cipher);
    }
}