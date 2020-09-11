using Org.BouncyCastle.Math;

namespace Cosmos.Encryption.Asymmetric
{
    public class SM2Result
    {
        public SM2Result() { }

        // 签名、验签
        public BigInteger r;
        public BigInteger s;
        public BigInteger R;
    }
}