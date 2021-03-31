using Org.BouncyCastle.Math;

// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Encryption
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