namespace Cosmos.Security.Cryptography
{
    public interface IRsaKeyConverter
    {
        /// <summary>
        /// Public Key Convert pem->xml
        /// </summary>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        string PublicKeyPemPkcs8ToXml(string publicKey);

        /// <summary>
        /// Public Key Convert xml->pem
        /// </summary>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        string PublicKeyXmlToPem(string publicKey);

        /// <summary>
        /// Private Key Convert Pkcs1->xml
        /// </summary>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        string PrivateKeyPkcs1ToXml(string privateKey);

        /// <summary>
        /// Private Key Convert xml->Pkcs1
        /// </summary>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        string PrivateKeyXmlToPkcs1(string privateKey);

        /// <summary>
        /// Private Key Convert Pkcs8->xml
        /// </summary>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        string PrivateKeyPkcs8ToXml(string privateKey);

        /// <summary>
        /// Private Key Convert xml->Pkcs8
        /// </summary>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        string PrivateKeyXmlToPkcs8(string privateKey);

        /// <summary>
        /// Private Key Convert Pkcs1->Pkcs8
        /// </summary>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        string PrivateKeyPkcs1ToPkcs8(string privateKey);

        /// <summary>
        /// Private Key Convert Pkcs8->Pkcs1
        /// </summary>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        string PrivateKeyPkcs8ToPkcs1(string privateKey);
    }
}