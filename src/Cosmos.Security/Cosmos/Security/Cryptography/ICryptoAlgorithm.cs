namespace Cosmos.Security.Cryptography
{
    /// <summary>
    /// Interface for Cryptography Algorithm
    /// </summary>
    public interface ICryptoAlgorithm
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