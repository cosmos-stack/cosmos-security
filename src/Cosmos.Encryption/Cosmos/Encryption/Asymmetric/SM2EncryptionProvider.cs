using System;
using Cosmos.Encryption.Core;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities.IO;

namespace Cosmos.Encryption.Asymmetric {
    /// <summary>
    /// SM2 encryption provider. BUG: THERE ARE SEVERAL BUG HERE, DO NOT USE THIS PROVIDER NOW!
    /// </summary>
    // ReSharper disable once InconsistentNaming
    public static class SM2EncryptionProvider {
        /// <summary>
        /// Signature
        /// </summary>
        /// <param name="data"></param>
        /// <param name="userId"></param>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public static byte[] Signature(byte[] data, byte[] userId, byte[] privateKey) {
            if (privateKey == null || privateKey.Length == 0)
                return null;

            if (data == null || data.Length == 0)
                return null;

            SM2 sm2 = SM2.Instance;
            BigInteger userD = new BigInteger(privateKey);

            ECPoint userKey = sm2.ecc_point_g.Multiply(userD);

            byte[] z = sm2.Sm2GetZ(userId, userKey);

            SM2_SM3Digest sm3 = new SM2_SM3Digest();
            sm3.BlockUpdate(z, 0, z.Length);
            sm3.BlockUpdate(data, 0, data.Length);
            byte[] md = new byte[32];
            sm3.DoFinal(md, 0);

            SM2.SM2Result sm2Result = new SM2.SM2Result();
            sm2.Sm2Sign(md, userD, userKey, sm2Result);

            DerInteger d_r = new DerInteger(sm2Result.r);
            DerInteger d_s = new DerInteger(sm2Result.s);
            Asn1EncodableVector v2 = new Asn1EncodableVector {d_r, d_s};
            DerSequence sign = new DerSequence(v2);
            return sign.GetEncoded();
        }


        /// <summary>
        /// Verify
        /// </summary>
        /// <param name="signedData"></param>
        /// <param name="data"></param>
        /// <param name="userId"></param>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public static bool Verify(byte[] signedData, byte[] data, byte[] userId, byte[] publicKey) {
            if (publicKey == null || publicKey.Length == 0)
                return false;

            if (data == null || data.Length == 0)
                return false;

            SM2 sm2 = SM2.Instance;
            ECPoint userKey = sm2.ecc_curve.DecodePoint(publicKey);

            SM2_SM3Digest sm3 = new SM2_SM3Digest();
            byte[] z = sm2.Sm2GetZ(userId, userKey);
            sm3.BlockUpdate(z, 0, z.Length);
            sm3.BlockUpdate(data, 0, data.Length);
            byte[] md = new byte[32];
            sm3.DoFinal(md, 0);

            MemoryInputStream bis = new MemoryInputStream(signedData);
            Asn1InputStream dis = new Asn1InputStream(bis);
            Asn1Object derObj = dis.ReadObject();
            var e = (Asn1Sequence) derObj;
            DerInteger r = (DerInteger) e[0];
            DerInteger s = (DerInteger) e[1];
            SM2.SM2Result sm2Result = new SM2.SM2Result();
            sm2Result.r = r.PositiveValue;
            sm2Result.s = s.PositiveValue;

            sm2.Sm2Verify(md, userKey, sm2Result.r, sm2Result.s, sm2Result);
            return Equals(sm2Result.r, sm2Result.R);
        }

        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="data"></param>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public static byte[] Encrypt(byte[] data, byte[] publicKey) {
            if (publicKey == null || publicKey.Length == 0)
                return null;

            if (data == null || data.Length == 0)
                return null;

            var source = new byte[data.Length];
            Array.Copy(data, 0, source, 0, data.Length);

            var cipher = new SM2.Cipher();
            var sm2 = SM2.Instance;
            ECPoint userKey = sm2.ecc_curve.DecodePoint(publicKey);

            ECPoint c1 = cipher.Init_enc(sm2, userKey);
            cipher.Encrypt(source);
            var c3 = new byte[3];
            cipher.Dofinal(c3);

            DerInteger x = new DerInteger(c1.XCoord.ToBigInteger());
            DerInteger y = new DerInteger(c1.YCoord.ToBigInteger());
            DerOctetString derDig = new DerOctetString(c3);
            DerOctetString derEnc = new DerOctetString(source);
            Asn1EncodableVector v = new Asn1EncodableVector {x, y, derDig, derEnc};
            DerSequence seq = new DerSequence(v);
            MemoryOutputStream bos = new MemoryOutputStream();
            DerOutputStream dos = new DerOutputStream(bos);
            dos.WriteObject(seq);
            return bos.ToArray();
        }

        /// <summary>
        /// Decrypt
        /// </summary>
        /// <param name="encryptedData"></param>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public static byte[] Decrypt(byte[] encryptedData, byte[] privateKey) {
            if (privateKey == null || privateKey.Length == 0)
                return null;

            if (encryptedData == null || encryptedData.Length == 0)
                return null;

            byte[] enc = new byte[encryptedData.Length];
            Array.Copy(encryptedData, 0, enc, 0, encryptedData.Length);

            SM2 sm2 = SM2.Instance;
            BigInteger userD = new BigInteger(1, privateKey);

            MemoryInputStream bis = new MemoryInputStream(enc);
            Asn1InputStream dis = new Asn1InputStream(bis);
            Asn1Object derObj = dis.ReadObject();
            Asn1Sequence asn1 = (Asn1Sequence) derObj;
            DerInteger x = (DerInteger) asn1[0];
            DerInteger y = (DerInteger) asn1[1];
            ECPoint c1 = sm2.ecc_curve.CreatePoint(x.PositiveValue, y.PositiveValue, true);

            SM2.Cipher cipher = new SM2.Cipher();
            cipher.Init_dec(userD, c1);
            DerOctetString data = (DerOctetString) asn1[3];
            enc = data.GetOctets();
            cipher.Decrypt(enc);
            byte[] c3 = new byte[32];
            cipher.Dofinal(c3);
            return enc;
        }
    }
}