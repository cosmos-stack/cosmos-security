namespace Cosmos.Security.Cryptography
{
    public static class RsaFactory
    {
        #region Generate Key

        /// <summary>
        /// Generate RSA key.
        /// </summary>
        /// <param name="mode"></param>
        /// <param name="keySize"></param>
        /// <param name="keyFormat"></param>
        /// <param name="keepingFormat"></param>
        /// <returns></returns>
        public static RsaKey GenerateKey(AsymmetricKeyMode mode, int keySize, RsaKeyFormat keyFormat = RsaKeyFormat.XML, bool keepingFormat = false) => RsaKeyGenerator.Generate(mode, keySize, keyFormat, keepingFormat);

        /// <summary>
        /// Generate RSA key.
        /// </summary>
        /// <param name="mode"></param>
        /// <param name="keySize"></param>
        /// <param name="keyFormat"></param>
        /// <param name="keepingFormat"></param>
        /// <returns></returns>
        public static RsaKey GenerateKey(AsymmetricKeyMode mode, RsaKeySize keySize, RsaKeyFormat keyFormat = RsaKeyFormat.XML, bool keepingFormat = false) => RsaKeyGenerator.Generate(mode, keySize, keyFormat, keepingFormat);

        /// <summary>
        /// Generate RSA public key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <param name="keyFormat"></param>
        /// <param name="keepingFormat"></param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKey(int keySize, RsaKeyFormat keyFormat = RsaKeyFormat.XML, bool keepingFormat = false) => RsaKeyGenerator.GeneratePublicKey(keySize, keyFormat, keepingFormat);

        /// <summary>
        /// Generate RSA public key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <param name="keyFormat"></param>
        /// <param name="keepingFormat"></param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKey(RsaKeySize keySize, RsaKeyFormat keyFormat = RsaKeyFormat.XML, bool keepingFormat = false) => RsaKeyGenerator.GeneratePrivateKey(keySize, keyFormat, keepingFormat);

        /// <summary>
        /// Generate RSA private key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <param name="keyFormat"></param>
        /// <param name="keepingFormat"></param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKey(int keySize, RsaKeyFormat keyFormat = RsaKeyFormat.XML, bool keepingFormat = false) => RsaKeyGenerator.GeneratePrivateKey(keySize, keyFormat, keepingFormat);

        /// <summary>
        /// Generate RSA private key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <param name="keyFormat"></param>
        /// <param name="keepingFormat"></param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKey(RsaKeySize keySize, RsaKeyFormat keyFormat = RsaKeyFormat.XML, bool keepingFormat = false) => RsaKeyGenerator.GeneratePublicKey(keySize, keyFormat, keepingFormat);

        /// <summary>
        /// Generate RSA private key.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="keyFormat"></param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKey(string key, RsaKeyFormat keyFormat = RsaKeyFormat.XML) => RsaKeyGenerator.GeneratePrivateKey(key, keyFormat);

        /// <summary>
        /// Generate RSA private key.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="keyFormat"></param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKey(string key, RsaKeyFormat keyFormat = RsaKeyFormat.XML) => RsaKeyGenerator.GeneratePublicKey(key, keyFormat);

        /// <summary>
        /// Generate XML Format RSA Key.
        /// </summary>
        /// <param name="mode"></param>
        /// <returns></returns>
        public static RsaKey GenerateKeyInXml(AsymmetricKeyMode mode) => RsaKeyGenerator.GenerateInXml(mode);

        /// <summary>
        /// Generate XML Format RSA Key.
        /// </summary>
        /// <param name="mode"></param>
        /// <param name="keySize">Key Size.Unit: bits</param>
        /// <returns></returns>
        public static RsaKey GenerateKeyInXml(AsymmetricKeyMode mode, int keySize) => RsaKeyGenerator.GenerateInXml(mode, keySize);

        /// <summary>
        /// Generate XML Format RSA Key.
        /// </summary>
        /// <param name="mode"></param>
        /// <param name="keySize"></param>
        /// <returns></returns>
        public static RsaKey GenerateKeyInXml(AsymmetricKeyMode mode, RsaKeySize keySize) => RsaKeyGenerator.GenerateInXml(mode, keySize);

        /// <summary>
        /// Generate XML Format RSA public key.
        /// </summary>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInXml() => RsaKeyGenerator.GeneratePublicKeyInXml();

        /// <summary>
        /// Generate XML Format RSA public key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInXml(int keySize) => RsaKeyGenerator.GeneratePublicKeyInXml(keySize);

        /// <summary>
        /// Generate XML Format RSA public key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInXml(RsaKeySize keySize) => RsaKeyGenerator.GeneratePublicKeyInXml(keySize);

        /// <summary>
        /// Generate XML Format RSA public key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInXml(string key) => RsaKeyGenerator.GeneratePublicKeyInXml(key);

        /// <summary>
        /// Generate XML Format RSA private key.
        /// </summary>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInXml() => RsaKeyGenerator.GeneratePrivateKeyInXml();

        /// <summary>
        /// Generate XML Format RSA private key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInXml(int keySize) => RsaKeyGenerator.GeneratePrivateKeyInXml(keySize);

        /// <summary>
        /// Generate XML Format RSA private key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInXml(RsaKeySize keySize) => RsaKeyGenerator.GeneratePrivateKeyInXml(keySize);

        /// <summary>
        /// Generate XML Format RSA private key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInXml(string key) => RsaKeyGenerator.GeneratePrivateKeyInXml(key);

        /// <summary>
        /// Generate JSON Format RSA Key.
        /// </summary>
        /// <param name="mode"></param>
        /// <returns></returns>
        public static RsaKey GenerateKeyInJson(AsymmetricKeyMode mode) => RsaKeyGenerator.GenerateInJson(mode);

        /// <summary>
        /// Generate JSON Format RSA Key.
        /// </summary>
        /// <param name="mode"></param>
        /// <param name="keySize"></param>
        /// <returns></returns>
        public static RsaKey GenerateKeyInJson(AsymmetricKeyMode mode, int keySize) => RsaKeyGenerator.GenerateInJson(mode, keySize);

        /// <summary>
        /// Generate JSON Format RSA Key.
        /// </summary>
        /// <param name="mode"></param>
        /// <param name="keySize">Key Size.Unit: bits</param>
        /// <returns></returns>
        public static RsaKey GenerateKeyInJson(AsymmetricKeyMode mode, RsaKeySize keySize) => RsaKeyGenerator.GenerateInJson(mode, keySize);

        /// <summary>
        /// Generate JSON Format RSA public key.
        /// </summary>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInJson() => RsaKeyGenerator.GeneratePublicKeyInJson();

        /// <summary>
        /// Generate JSON Format RSA public key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInJson(int keySize) => RsaKeyGenerator.GeneratePublicKeyInJson(keySize);

        /// <summary>
        /// Generate JSON Format RSA public key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInJson(RsaKeySize keySize) => RsaKeyGenerator.GeneratePublicKeyInJson(keySize);

        /// <summary>
        /// Generate JSON Format RSA public key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInJson(string key) => RsaKeyGenerator.GeneratePublicKeyInJson(key);

        /// <summary>
        /// Generate JSON Format RSA private key.
        /// </summary>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInJson() => RsaKeyGenerator.GeneratePrivateKeyInJson();

        /// <summary>
        /// Generate JSON Format RSA private key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInJson(int keySize) => RsaKeyGenerator.GeneratePrivateKeyInJson(keySize);

        /// <summary>
        /// Generate JSON Format RSA private key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInJson(RsaKeySize keySize) => RsaKeyGenerator.GeneratePrivateKeyInJson(keySize);

        /// <summary>
        /// Generate JSON Format RSA private key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInJson(string key) => RsaKeyGenerator.GeneratePrivateKeyInJson(key);

        /// <summary>
        /// Generate RSA key in Pkcs1 format.
        /// </summary>
        /// <param name="mode"></param>
        /// <param name="keepingFormat">Whether the format is true If it is standard pem file format</param>
        /// <returns></returns>
        public static RsaKey GenerateKeyInPkcs1(AsymmetricKeyMode mode, bool keepingFormat) => RsaKeyGenerator.GenerateInPkcs1(mode, keepingFormat);

        /// <summary>
        /// Generate RSA key in Pkcs1 format.
        /// </summary>
        /// <param name="mode"></param>
        /// <param name="keySize">Key Size.Unit: bits</param>
        /// <param name="keepingFormat">Whether the format is true If it is standard pem file format</param>
        /// <returns></returns>
        public static RsaKey GenerateKeyInPkcs1(AsymmetricKeyMode mode, int keySize, bool keepingFormat) => RsaKeyGenerator.GenerateInPkcs1(mode, keySize, keepingFormat);

        /// <summary>
        /// Generate RSA key in Pkcs1 format.
        /// </summary>
        /// <param name="mode"></param>
        /// <param name="keySize">Key Size.Unit: bits</param>
        /// <param name="keepingFormat">Whether the format is true If it is standard pem file format</param>
        /// <returns></returns>
        public static RsaKey GenerateKeyInPkcs1(AsymmetricKeyMode mode, RsaKeySize keySize, bool keepingFormat) => RsaKeyGenerator.GenerateInPkcs1(mode, keySize, keepingFormat);

        /// <summary>
        /// Generate Pkcs1 format RSA public key.
        /// </summary>
        /// <param name="keepingFormat">Whether the format is true If it is standard pem file format</param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInPkcs1(bool keepingFormat) => RsaKeyGenerator.GeneratePublicKeyInPkcs1(keepingFormat);

        /// <summary>
        /// Generate Pkcs1 format RSA public key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <param name="keepingFormat"></param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInPkcs1(int keySize, bool keepingFormat) => RsaKeyGenerator.GeneratePublicKeyInPkcs1(keySize, keepingFormat);

        /// <summary>
        /// Generate Pkcs1 format RSA public key.
        /// </summary>
        /// <param name="keySize">Key Size.Unit: bits</param>
        /// <param name="keepingFormat">Whether the format is true If it is standard pem file format</param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInPkcs1(RsaKeySize keySize, bool keepingFormat) => RsaKeyGenerator.GeneratePublicKeyInPkcs1(keySize, keepingFormat);

        /// <summary>
        /// Generate Pkcs1 format RSA public key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInPkcs1(string key) => RsaKeyGenerator.GeneratePublicKeyInPkcs1(key);

        /// <summary>
        /// Generate Pkcs1 format RSA private key.
        /// </summary>
        /// <param name="keepingFormat">Whether the format is true If it is standard pem file format</param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInPkcs1(bool keepingFormat) => RsaKeyGenerator.GeneratePrivateKeyInPkcs1(keepingFormat);

        /// <summary>
        /// Generate Pkcs1 format RSA private key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <param name="keepingFormat"></param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInPkcs1(int keySize, bool keepingFormat) => RsaKeyGenerator.GeneratePrivateKeyInPkcs1(keySize, keepingFormat);

        /// <summary>
        /// Generate Pkcs1 format RSA private key.
        /// </summary>
        /// <param name="keySize">Key Size.Unit: bits</param>
        /// <param name="keepingFormat">Whether the format is true If it is standard pem file format</param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInPkcs1(RsaKeySize keySize, bool keepingFormat) => RsaKeyGenerator.GeneratePrivateKeyInPkcs1(keySize, keepingFormat);

        /// <summary>
        /// Generate Pkcs1 format RSA private key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInPkcs1(string key) => RsaKeyGenerator.GeneratePrivateKeyInPkcs1(key);

        /// <summary>
        /// Generate Pkcs8 format RSA key.
        /// </summary>
        /// <param name="mode"></param>
        /// <param name="keepingFormat">Whether the format is true If it is standard pem file format</param>
        /// <returns></returns>
        public static RsaKey GenerateKeyInPkcs8(AsymmetricKeyMode mode, bool keepingFormat) => RsaKeyGenerator.GenerateInPkcs8(mode, keepingFormat);

        /// <summary>
        /// Generate Pkcs8 format RSA key.
        /// </summary>
        /// <param name="mode"></param>
        /// <param name="keySize">Key Size.Unit: bits</param>
        /// <param name="keepingFormat">Whether the format is true If it is standard pem file format</param>
        /// <returns></returns>
        public static RsaKey GenerateKeyInPkcs8(AsymmetricKeyMode mode, int keySize, bool keepingFormat) => RsaKeyGenerator.GenerateInPkcs8(mode, keySize, keepingFormat);

        /// <summary>
        /// Generate Pkcs8 format RSA key.
        /// </summary>
        /// <param name="mode"></param>
        /// <param name="keySize">Key Size.Unit: bits</param>
        /// <param name="keepingFormat">Whether the format is true If it is standard pem file format</param>
        /// <returns></returns>
        public static RsaKey GenerateKeyInPkcs8(AsymmetricKeyMode mode, RsaKeySize keySize, bool keepingFormat) => RsaKeyGenerator.GenerateInPkcs8(mode, keySize, keepingFormat);

        /// <summary>
        /// Generate Pkcs8 format RSA public key.
        /// </summary>
        /// <param name="keepingFormat">Whether the format is true If it is standard pem file format</param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInPkcs8(bool keepingFormat) => RsaKeyGenerator.GeneratePublicKeyInPkcs8(keepingFormat);

        /// <summary>
        /// Generate Pkcs8 format RSA public key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <param name="keepingFormat"></param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInPkcs8(int keySize, bool keepingFormat) => RsaKeyGenerator.GeneratePublicKeyInPkcs8(keySize, keepingFormat);

        /// <summary>
        /// Generate Pkcs8 format RSA public key.
        /// </summary>
        /// <param name="keySize">Key Size.Unit: bits</param>
        /// <param name="keepingFormat">Whether the format is true If it is standard pem file format</param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInPkcs8(RsaKeySize keySize, bool keepingFormat) => RsaKeyGenerator.GeneratePublicKeyInPkcs8(keySize, keepingFormat);

        /// <summary>
        /// Generate Pkcs8 format RSA public key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInPkcs8(string key) => RsaKeyGenerator.GeneratePublicKeyInPkcs8(key);

        /// <summary>
        /// Generate Pkcs8 format RSA private key.
        /// </summary>
        /// <param name="keepingFormat">Whether the format is true If it is standard pem file format</param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInPkcs8(bool keepingFormat) => RsaKeyGenerator.GeneratePrivateKeyInPkcs8(keepingFormat);

        /// <summary>
        /// Generate Pkcs8 format RSA private key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <param name="keepingFormat"></param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInPkcs8(int keySize, bool keepingFormat) => RsaKeyGenerator.GeneratePrivateKeyInPkcs8(keySize, keepingFormat);

        /// <summary>
        /// Generate Pkcs8 format RSA private key.
        /// </summary>
        /// <param name="keySize">Key Size.Unit: bits</param>
        /// <param name="keepingFormat">Whether the format is true If it is standard pem file format</param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInPkcs8(RsaKeySize keySize, bool keepingFormat) => RsaKeyGenerator.GeneratePrivateKeyInPkcs8(keySize, keepingFormat);

        /// <summary>
        /// Generate Pkcs8 format RSA private key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInPkcs8(string key) => RsaKeyGenerator.GeneratePrivateKeyInPkcs8(key);

        /// <summary>
        /// Get private key of xml format from certificate file.
        /// </summary>
        /// <param name="certFile">The string path of certificate file.</param>
        /// <param name="password">The string password of certificate file.</param>
        /// <returns>String private key of xml format.</returns>
        public static RsaKey GeneratePrivateKeyFromFile(string certFile, string password) => RsaKeyGenerator.GeneratePrivateKeyFromFile(certFile, password);

        /// <summary>
        /// Get public key of xml format from certificate file.
        /// </summary>
        /// <param name="certFile">The string path of certificate file.</param>
        /// <returns>String public key of xml format.</returns>
        public static RsaKey GeneratePublicKeyFromFile(string certFile) => RsaKeyGenerator.GeneratePublicKeyFromFile(certFile);

        #endregion

        #region Create

        public static IRSA Create(RsaKey key) => new RsaFunction(key);

        public static IRSA CreateWithPublicKey(string key, RsaKeyFormat keyFormat) => new RsaFunction(RsaKeyGenerator.GeneratePublicKey(key, keyFormat));
        
        public static IRSA CreateWithPrivateKey(string key, RsaKeyFormat keyFormat) => new RsaFunction(RsaKeyGenerator.GeneratePrivateKey(key, keyFormat));

        public static IRSA CreateWithKeyInXml(string key) => new RsaFunction(RsaKeyGenerator.GenerateInXml(key));

        public static IRSA CreateWithPublicKeyInXml(string key) => new RsaFunction(RsaKeyGenerator.GeneratePublicKeyInXml(key));

        public static IRSA CreateWithPrivateKeyInXml(string key) => new RsaFunction(RsaKeyGenerator.GeneratePrivateKeyInXml(key));

        public static IRSA CreateWithKeyInJson(string key) => new RsaFunction(RsaKeyGenerator.GenerateInJson(key));

        public static IRSA CreateWithPublicKeyInJson(string key) => new RsaFunction(RsaKeyGenerator.GeneratePublicKeyInJson(key));

        public static IRSA CreateWithPrivateKeyInJson(string key) => new RsaFunction(RsaKeyGenerator.GeneratePrivateKeyInJson(key));

        public static IRSA CreateWithPublicKeyInPkcs1(string key) => new RsaFunction(RsaKeyGenerator.GeneratePublicKeyInPkcs1(key));

        public static IRSA CreateWithPrivateKeyInPkcs1(string key) => new RsaFunction(RsaKeyGenerator.GeneratePrivateKeyInPkcs1(key));

        public static IRSA CreateWithPublicKeyInPkcs8(string key) => new RsaFunction(RsaKeyGenerator.GeneratePublicKeyInPkcs8(key));

        public static IRSA CreateWithPrivateKeyInPkcs8(string key) => new RsaFunction(RsaKeyGenerator.GeneratePrivateKeyInPkcs8(key));

        public static IRSA CreateWithPublicKeyFromFile(string certFile) => new RsaFunction(RsaKeyGenerator.GeneratePublicKeyFromFile(certFile));

        public static IRSA CreateWithPrivateKeyFromFile(string certFile, string password) => new RsaFunction(RsaKeyGenerator.GeneratePrivateKeyFromFile(certFile, password));

        #endregion
    }
}