using Cosmos.Encryption.Core;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.IO;

namespace Cosmos.Encryption.Asymmetric
{
    /// <summary>
    /// SM2 encryption provider.
    /// </summary>
    // ReSharper disable once InconsistentNaming
    public static partial class SM2EncryptionProvider
    {
        /// <summary>
        /// Verify<br />
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="privateKey"></param>
        /// <param name="sourceData"></param>
        /// <param name="signData"></param>
        /// <returns></returns>
        public static bool Verify2(byte[] userId, byte[] privateKey, byte[] sourceData, byte[] signData)
        {
            if (privateKey is null || privateKey.Length == 0)
                return false;

            if (sourceData is null || sourceData.Length == 0)
                return false;

            SM2Core sm2 = SM2Core.Instance;
            ECPoint userKey = sm2.ecc_curve.DecodePoint(Hex.Encode(privateKey));

            SM2Core.SM2_SM3Digest sm3 = new SM2Core.SM2_SM3Digest();
            byte[] z = sm2.Sm2GetZ(userId, userKey);
            sm3.BlockUpdate(z, 0, z.Length);
            sm3.BlockUpdate(sourceData, 0, sourceData.Length);
            byte[] md = new byte[32];
            sm3.DoFinal(md, 0);

            MemoryInputStream bis = new MemoryInputStream(signData);
            Asn1InputStream dis = new Asn1InputStream(bis);
            Asn1Object derObj = dis.ReadObject();
            var e = (Asn1Sequence) derObj;
            DerInteger r = (DerInteger) e[0];
            DerInteger s = (DerInteger) e[1];
            SM2Result sm2Result = new SM2Result();
            sm2Result.r = r.PositiveValue;
            sm2Result.s = s.PositiveValue;

            sm2.Sm2Verify(md, userKey, sm2Result.r, sm2Result.s, sm2Result);
            return sm2Result.r.Equals(sm2Result.R);
        }
    }
}