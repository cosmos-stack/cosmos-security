using System.Text;
using Cosmos.Security.Encryption.Core;
using Org.BouncyCastle.Crypto.Parameters;

// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Encryption
{
    /// <summary>
    /// SM2 encryption provider.
    /// </summary>
    // ReSharper disable once InconsistentNaming
    public static partial class SM2EncryptionProvider
    {
        /// <summary>
        /// Create a new <see cref="RSAKey"/>
        /// </summary>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public static SM2Key CreateKey(Encoding encoding = default)
        {
            var sm2 = SM2Core.Instance;
            var key = sm2.ecc_key_pair_generator.GenerateKeyPair();
            var ecPriv = (ECPrivateKeyParameters) key.Private;
            var ecPub = (ECPublicKeyParameters) key.Public;

            return new SM2Key(ecPub.Q, ecPriv.D, encoding);
        }
    }
}