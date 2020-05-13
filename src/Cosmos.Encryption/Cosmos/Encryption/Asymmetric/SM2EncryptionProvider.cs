using System;
using System.Text;
using Cosmos.Encryption.Core;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.IO;
using Cosmos.Optionals;

namespace Cosmos.Encryption.Asymmetric {
    /// <summary>
    /// SM2 encryption provider.
    /// </summary>
    // ReSharper disable once InconsistentNaming
    public static class SM2EncryptionProvider {
        /// <summary>
        /// Signature<br />
        /// BUG: THERE ARE SEVERAL BUG HERE, DO NOT USE THIS PROVIDER NOW!
        /// </summary>
        /// <param name="data"></param>
        /// <param name="userId"></param>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public static byte[] Signature(byte[] data, byte[] userId, byte[] privateKey) {
            if (privateKey is null || privateKey.Length == 0)
                return null;

            if (data is null || data.Length == 0)
                return null;

            SM2Core sm2 = SM2Core.Instance;

            BigInteger userD = new BigInteger(privateKey);

            ECPoint userKey = sm2.ecc_point_g.Multiply(userD);

            byte[] z = sm2.Sm2GetZ(userId, userKey);


            SM2Core.SM2_SM3Digest sm3 = new SM2Core.SM2_SM3Digest();
            sm3.BlockUpdate(z, 0, z.Length);
            sm3.BlockUpdate(data, 0, data.Length);
            byte[] md = new byte[32];
            sm3.DoFinal(md, 0);

            SM2Core.SM2Result sm2Result = new SM2Core.SM2Result();
            sm2.Sm2Sign(md, userD, userKey, sm2Result);

            DerInteger d_r = new DerInteger(sm2Result.r);
            DerInteger d_s = new DerInteger(sm2Result.s);
            Asn1EncodableVector v2 = new Asn1EncodableVector {d_r, d_s};
            DerSequence sign = new DerSequence(v2);
            return sign.GetEncoded();
        }

        /// <summary>
        /// Verify<br />
        /// BUG: THERE ARE SEVERAL BUG HERE, DO NOT USE THIS PROVIDER NOW!
        /// </summary>
        /// <param name="signedData"></param>
        /// <param name="data"></param>
        /// <param name="userId"></param>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public static bool Verify(byte[] signedData, byte[] data, byte[] userId, byte[] publicKey) {
            if (publicKey is null || publicKey.Length == 0)
                return false;

            if (data is null || data.Length == 0)
                return false;

            SM2Core sm2 = SM2Core.Instance;
            ECPoint userKey = sm2.ecc_curve.DecodePoint(publicKey);

            SM2Core.SM2_SM3Digest sm3 = new SM2Core.SM2_SM3Digest();
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
            SM2Core.SM2Result sm2Result = new SM2Core.SM2Result();
            sm2Result.r = r.PositiveValue;
            sm2Result.s = s.PositiveValue;

            sm2.Sm2Verify(md, userKey, sm2Result.r, sm2Result.s, sm2Result);
            return Equals(sm2Result.r, sm2Result.R);
        }


        /// <summary>
        /// Encrypt by public key
        /// </summary>
        /// <param name="data"></param>
        /// <param name="publicKey"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public static string EncryptByPublicKey(string data, string publicKey, Encoding encoding = default) {
            if (publicKey is null || publicKey.Length == 0)
                return null;

            if (data is null || data.Length == 0)
                return null;

            // ReSharper disable once ExpressionIsAlwaysNull
            encoding ??= encoding.SafeValue();

            return EncryptByPublicKey(encoding.GetBytes(data), publicKey, encoding);
        }

        /// <summary>
        /// Encrypt by public key
        /// </summary>
        /// <param name="dataBytes"></param>
        /// <param name="publicKey"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public static string EncryptByPublicKey(byte[] dataBytes, string publicKey, Encoding encoding = default) {
            if (publicKey is null || publicKey.Length == 0)
                return null;

            if (dataBytes is null || dataBytes.Length == 0)
                return null;

            // ReSharper disable once ExpressionIsAlwaysNull
            encoding ??= encoding.SafeValue();

            var publicKeyBytes = Hex.Decode(encoding.GetBytes(publicKey));

            var source = new byte[dataBytes.Length];
            Array.Copy(dataBytes, 0, source, 0, dataBytes.Length);

            var cipher = new SM2Core.Cipher();
            var sm2 = SM2Core.Instance;

            var userKey = sm2.ecc_curve.DecodePoint(publicKeyBytes);

            var c1 = cipher.Init_enc(sm2, userKey);
            cipher.Encrypt(source);

            var c3 = new byte[32];
            cipher.Dofinal(c3);

            var sc1 = encoding.GetString(Hex.Encode(c1.GetEncoded()));
            var sc2 = encoding.GetString(Hex.Encode(source));
            var sc3 = encoding.GetString(Hex.Encode(c3));

            return (sc1 + sc2 + sc3).ToUpper();
        }

        /// <summary>
        /// Encrypt by public key
        /// </summary>
        /// <param name="data"></param>
        /// <param name="publicKey"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public static byte[] EncryptByPublicKeyAsBytes(string data, string publicKey, Encoding encoding = default) {
            if (publicKey is null || publicKey.Length == 0)
                return null;

            if (data is null || data.Length == 0)
                return null;

            // ReSharper disable once ExpressionIsAlwaysNull
            encoding ??= encoding.SafeValue();

            return encoding.GetBytes(EncryptByPublicKey(encoding.GetBytes(data), publicKey, encoding));
        }

        /// <summary>
        /// Encrypt by public key
        /// </summary>
        /// <param name="dataBytes"></param>
        /// <param name="publicKey"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public static byte[] EncryptByPublicKeyAsBytes(byte[] dataBytes, string publicKey, Encoding encoding = default) {
            if (publicKey is null || publicKey.Length == 0)
                return null;

            if (dataBytes is null || dataBytes.Length == 0)
                return null;

            // ReSharper disable once ExpressionIsAlwaysNull
            encoding ??= encoding.SafeValue();

            return encoding.GetBytes(EncryptByPublicKey(dataBytes, publicKey, encoding));
        }

        /// <summary>
        /// Decrypt by private key
        /// </summary>
        /// <param name="data"></param>
        /// <param name="privateKey"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public static string DecryptByPrivateKey(string data, string privateKey, Encoding encoding = default) {
            if (privateKey is null || privateKey.Length == 0)
                return null;

            if (data is null || data.Length == 0)
                return null;

            // ReSharper disable once ExpressionIsAlwaysNull
            encoding ??= encoding.SafeValue();

            return DecryptByPrivateKeyAsBytes(encoding.GetBytes(data), privateKey, encoding).GetString(encoding);
        }

        /// <summary>
        /// Decrypt by private key
        /// </summary>
        /// <param name="dataBytes"></param>
        /// <param name="privateKey"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public static string DecryptByPrivateKey(byte[] dataBytes, string privateKey, Encoding encoding = default) {
            if (privateKey is null || privateKey.Length == 0)
                return null;

            if (dataBytes is null || dataBytes.Length == 0)
                return null;

            // ReSharper disable once ExpressionIsAlwaysNull
            encoding ??= encoding.SafeValue();

            return DecryptByPrivateKeyAsBytes(dataBytes, privateKey, encoding).GetString(encoding);
        }

        /// <summary>
        /// Decrypt by private key
        /// </summary>
        /// <param name="data"></param>
        /// <param name="privateKey"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public static byte[] DecryptByPrivateKeyAsBytes(string data, string privateKey, Encoding encoding = default) {
            if (privateKey is null || privateKey.Length == 0)
                return null;

            if (data is null || data.Length == 0)
                return null;

            // ReSharper disable once ExpressionIsAlwaysNull
            encoding ??= encoding.SafeValue();

            return DecryptByPrivateKeyAsBytes(encoding.GetBytes(data), privateKey, encoding);
        }

        /// <summary>
        /// Decrypt by private key
        /// </summary>
        /// <param name="dataBytes"></param>
        /// <param name="privateKey"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public static byte[] DecryptByPrivateKeyAsBytes(byte[] dataBytes, string privateKey, Encoding encoding = default) {
            if (privateKey is null || privateKey.Length == 0)
                return null;

            if (dataBytes is null || dataBytes.Length == 0)
                return null;

            // ReSharper disable once ExpressionIsAlwaysNull
            encoding ??= encoding.SafeValue();

            var privateKeyBytes = Hex.Decode(encoding.GetBytes(privateKey));
            var source = Hex.Decode(dataBytes);
            var data = dataBytes.GetString(encoding);

            var c1Bytes = Hex.Decode(encoding.GetBytes(data.Substring(0, 130)));
            var c2Len = source.Length - 97;
            var c2 = Hex.Decode(Encoding.UTF8.GetBytes(data.Substring(130, 2 * c2Len)));
            var c3 = Hex.Decode(Encoding.UTF8.GetBytes(data.Substring(130 + 2 * c2Len, 64)));

            var sm2 = SM2Core.Instance;
            var userD = new BigInteger(1, privateKeyBytes);

            var c1 = sm2.ecc_curve.DecodePoint(c1Bytes);
            var cipher = new SM2Core.Cipher();
            cipher.Init_dec(userD, c1);
            cipher.Decrypt(c2);
            cipher.Dofinal(c3);

            return c2;
        }
    }
}