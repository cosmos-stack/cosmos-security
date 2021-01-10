using Org.BouncyCastle.Math;

namespace Cosmos.Encryption.Asymmetric
{
    // ReSharper disable InconsistentNaming
    public class SM2Result
    {
        // 签名、验签
        public BigInteger r;
        public BigInteger s;
        public BigInteger R;
    }
}