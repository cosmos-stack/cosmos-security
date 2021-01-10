using Cosmos.Encryption.Core;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities.Encoders;
// ReSharper disable InconsistentNaming

namespace Cosmos.Encryption.Asymmetric
{
    /// <summary>
    /// SM2 encryption provider.
    /// </summary>
    // ReSharper disable once InconsistentNaming
    public static partial class SM2EncryptionProvider
    {
        /// <summary>
        /// Signature
        /// </summary>
        /// <param name="data"></param>
        /// <param name="userId"></param>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public static byte[] Signature2(byte[] data, byte[] userId, byte[] publicKey)
        {
            if (publicKey is null || publicKey.Length == 0)
                return null;

            if (data is null || data.Length == 0)
                return null;

            SM2Core sm2 = SM2Core.Instance;
            BigInteger userD = new BigInteger(Hex.Decode(publicKey));
            ECPoint userKey = sm2.ecc_point_g.Multiply(userD);

            SM2Core.SM2_SM3Digest sm3 = new SM2Core.SM2_SM3Digest();
            byte[] z = sm2.Sm2GetZ(userId, userKey);

            sm3.BlockUpdate(z, 0, z.Length);
            sm3.BlockUpdate(data, 0, data.Length);
            byte[] md = new byte[32];
            sm3.DoFinal(md, 0);

            SM2Result sm2Result = new SM2Result();
            sm2.Sm2Sign(md, userD, userKey, sm2Result);

            DerInteger d_r = new DerInteger(sm2Result.r);
            DerInteger d_s = new DerInteger(sm2Result.s);
            Asn1EncodableVector v2 = new Asn1EncodableVector();
            v2.Add(d_r);
            v2.Add(d_s);
            DerSequence sign = new DerSequence(v2);
            byte[] signdata = sign.GetEncoded();
            return signdata;
        }
    }
}