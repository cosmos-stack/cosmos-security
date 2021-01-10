using System.Text;
using Cosmos.Optionals;
using Cosmos.Text;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities.Encoders;

namespace Cosmos.Encryption.Asymmetric
{
    // ReSharper disable once InconsistentNaming
    public class SM2Key
    {
        internal SM2Key(ECPoint publicKey, BigInteger privateKey, Encoding encoding = default)
        {
            PublicKey = Hex.Encode(publicKey.GetEncoded()).GetString(encoding.SafeValue()).ToUpper();
            PrivateKey = Hex.Encode(privateKey.ToByteArray()).GetString(encoding.SafeValue()).ToUpper();
        }

        /// <summary>
        /// SM2 public key
        /// </summary>
        public string PublicKey { get; set; }

        /// <summary>
        /// SM2 private key
        /// </summary>
        public string PrivateKey { get; set; }
    }
}