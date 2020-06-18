using System;
using System.Collections.Generic;
using System.Text;
using Cosmos.Encryption.Core;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.IO;
using Cosmos.Optionals;

namespace Cosmos.Encryption.Asymmetric
{
    /// <summary>
    /// SM2 encryption provider.
    /// </summary>
    // ReSharper disable once InconsistentNaming
    public static partial class SM2EncryptionProvider
    {
        //         /// <summary>
        //         /// Signature<br />
        //         /// BUG: THERE ARE SEVERAL BUG HERE, DO NOT USE THIS PROVIDER NOW!
        //         /// </summary>
        //         /// <param name="data"></param>
        //         /// <param name="userId"></param>
        //         /// <param name="publicKey"></param>
        //         /// <returns></returns>
        //         public static byte[] Signature(byte[] data, byte[] userId, byte[] publicKey) {
        //             if (publicKey is null || publicKey.Length == 0)
        //                 return null;
        //
        //             if (data is null || data.Length == 0)
        //                 return null;
        //
        //             SM2Core sm2 = SM2Core.Instance;
        //
        //             BigInteger userD = new BigInteger(publicKey);
        //
        //             ECPoint userKey = sm2.ecc_point_g.Multiply(userD); //sm2.ecc_point_g.Multiply(userD);
        //
        //             byte[] z = sm2.Sm2GetZ(userId, userKey);
        //
        //             SM2Core.SM2_SM3Digest sm3 = new SM2Core.SM2_SM3Digest();
        //             sm3.BlockUpdate(z, 0, z.Length);
        //             sm3.BlockUpdate(data, 0, data.Length);
        //             byte[] md = new byte[32];
        //             sm3.DoFinal(md, 0);
        //
        //             SM2Core.SM2Result sm2Result = new SM2Core.SM2Result();
        //             sm2.Sm2Sign(md, userD, userKey, sm2Result);
        //
        //             DerInteger d_r = new DerInteger(sm2Result.r);
        //             DerInteger d_s = new DerInteger(sm2Result.s);
        //             Asn1EncodableVector v2 = new Asn1EncodableVector {d_r, d_s};
        //             DerSequence sign = new DerSequence(v2);
        //             return sign.GetEncoded();
        //         }
        //
        //         /// <summary>
        //         /// Verify<br />
        //         /// BUG: THERE ARE SEVERAL BUG HERE, DO NOT USE THIS PROVIDER NOW!
        //         /// </summary>
        //         /// <param name="signedData"></param>
        //         /// <param name="data"></param>
        //         /// <param name="userId"></param>
        //         /// <param name="privateKey"></param>
        //         /// <returns></returns>
        //         public static bool Verify(byte[] signedData, byte[] data, byte[] userId, byte[] privateKey) {
        //             if (privateKey is null || privateKey.Length == 0)
        //                 return false;
        //
        //             if (data is null || data.Length == 0)
        //                 return false;
        //
        //             SM2Core sm2 = SM2Core.Instance;
        //             ECPoint userKey = sm2.ecc_curve.DecodePoint(privateKey);
        // //Hex.Decode(encoding.GetBytes(privateKey))
        //             SM2Core.SM2_SM3Digest sm3 = new SM2Core.SM2_SM3Digest();
        //             byte[] z = sm2.Sm2GetZ(userId, userKey);
        //             sm3.BlockUpdate(z, 0, z.Length);
        //             sm3.BlockUpdate(data, 0, data.Length);
        //             byte[] md = new byte[32];
        //             sm3.DoFinal(md, 0);
        //
        //             MemoryInputStream bis = new MemoryInputStream(signedData);
        //             Asn1InputStream dis = new Asn1InputStream(bis);
        //             Asn1Object derObj = dis.ReadObject();
        //             var e = (Asn1Sequence) derObj;
        //             DerInteger r = (DerInteger) e[0];
        //             DerInteger s = (DerInteger) e[1];
        //             SM2Core.SM2Result sm2Result = new SM2Core.SM2Result();
        //             sm2Result.r = r.PositiveValue;
        //             sm2Result.s = s.PositiveValue;
        //
        //             sm2.Sm2Verify(md, userKey, sm2Result.r, sm2Result.s, sm2Result);
        //             return Equals(sm2Result.r, sm2Result.R);
        //         }

        /// <summary>
        /// Signature<br />
        /// BUG: THERE ARE SEVERAL BUG HERE, DO NOT USE THIS PROVIDER NOW!
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

            SM2Core.SM2Result sm2Result = new SM2Core.SM2Result();
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

        /// <summary>
        /// Verify<br />
        /// BUG: THERE ARE SEVERAL BUG HERE, DO NOT USE THIS PROVIDER NOW!
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
            SM2Core.SM2Result sm2Result = new SM2Core.SM2Result();
            sm2Result.r = r.PositiveValue;
            sm2Result.s = s.PositiveValue;

            sm2.Sm2Verify(md, userKey, sm2Result.r, sm2Result.s, sm2Result);
            return sm2Result.r.Equals(sm2Result.R);
        }

        /// <summary>
        /// Encrypt by public key
        /// </summary>
        /// <param name="data"></param>
        /// <param name="publicKey"></param>
        /// <param name="encoding"></param>
        /// <param name="mode"></param>
        /// <returns></returns>
        public static string EncryptByPublicKey(string data, string publicKey, Encoding encoding = default, SM2Mode mode = SM2Mode.C1C3C2)
        {
            if (publicKey is null || publicKey.Length == 0)
                return null;

            if (data is null || data.Length == 0)
                return null;

            // ReSharper disable once ExpressionIsAlwaysNull
            encoding ??= encoding.SafeValue();

            return EncryptByPublicKey(encoding.GetBytes(data), publicKey, encoding, mode);
        }

        /// <summary>
        /// Encrypt by public key
        /// </summary>
        /// <param name="dataBytes"></param>
        /// <param name="publicKey"></param>
        /// <param name="encoding"></param>
        /// <param name="mode"></param>
        /// <returns></returns>
        public static string EncryptByPublicKey(byte[] dataBytes, string publicKey, Encoding encoding = default, SM2Mode mode = SM2Mode.C1C3C2)
        {
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

            var c1Str = encoding.GetString(Hex.Encode(c1.GetEncoded()));
            var c2Str = encoding.GetString(Hex.Encode(source));
            var c3Str = encoding.GetString(Hex.Encode(c3));

            return mode == SM2Mode.C1C2C3
                ? (c1Str + c2Str + c3Str).ToUpper()
                : (c1Str + c3Str + c2Str).ToUpper();
        }

        /// <summary>
        /// Encrypt by public key
        /// </summary>
        /// <param name="data"></param>
        /// <param name="publicKey"></param>
        /// <param name="encoding"></param>
        /// <param name="mode"></param>
        /// <returns></returns>
        public static byte[] EncryptByPublicKeyAsBytes(string data, string publicKey, Encoding encoding = default, SM2Mode mode = SM2Mode.C1C3C2)
        {
            if (publicKey is null || publicKey.Length == 0)
                return null;

            if (data is null || data.Length == 0)
                return null;

            // ReSharper disable once ExpressionIsAlwaysNull
            encoding ??= encoding.SafeValue();

            return encoding.GetBytes(EncryptByPublicKey(encoding.GetBytes(data), publicKey, encoding, mode));
        }

        /// <summary>
        /// Encrypt by public key
        /// </summary>
        /// <param name="dataBytes"></param>
        /// <param name="publicKey"></param>
        /// <param name="encoding"></param>
        /// <param name="mode"></param>
        /// <returns></returns>
        public static byte[] EncryptByPublicKeyAsBytes(byte[] dataBytes, string publicKey, Encoding encoding = default, SM2Mode mode = SM2Mode.C1C3C2)
        {
            if (publicKey is null || publicKey.Length == 0)
                return null;

            if (dataBytes is null || dataBytes.Length == 0)
                return null;

            // ReSharper disable once ExpressionIsAlwaysNull
            encoding ??= encoding.SafeValue();

            return encoding.GetBytes(EncryptByPublicKey(dataBytes, publicKey, encoding, mode));
        }

        /// <summary>
        /// Decrypt by private key
        /// </summary>
        /// <param name="data"></param>
        /// <param name="privateKey"></param>
        /// <param name="encoding"></param>
        /// <param name="mode"></param>
        /// <returns></returns>
        public static string DecryptByPrivateKey(string data, string privateKey, Encoding encoding = default, SM2Mode mode = SM2Mode.C1C3C2)
        {
            if (privateKey is null || privateKey.Length == 0)
                return null;

            if (data is null || data.Length == 0)
                return null;

            // ReSharper disable once ExpressionIsAlwaysNull
            encoding ??= encoding.SafeValue();

            return DecryptByPrivateKeyAsBytes(encoding.GetBytes(data), privateKey, encoding, mode).GetString(encoding);
        }

        /// <summary>
        /// Decrypt by private key
        /// </summary>
        /// <param name="dataBytes"></param>
        /// <param name="privateKey"></param>
        /// <param name="encoding"></param>
        /// <param name="mode"></param>
        /// <returns></returns>
        public static string DecryptByPrivateKey(byte[] dataBytes, string privateKey, Encoding encoding = default, SM2Mode mode = SM2Mode.C1C3C2)
        {
            if (privateKey is null || privateKey.Length == 0)
                return null;

            if (dataBytes is null || dataBytes.Length == 0)
                return null;

            // ReSharper disable once ExpressionIsAlwaysNull
            encoding ??= encoding.SafeValue();

            return DecryptByPrivateKeyAsBytes(dataBytes, privateKey, encoding, mode).GetString(encoding);
        }

        /// <summary>
        /// Decrypt by private key
        /// </summary>
        /// <param name="data"></param>
        /// <param name="privateKey"></param>
        /// <param name="encoding"></param>
        /// <param name="mode"></param>
        /// <returns></returns>
        public static byte[] DecryptByPrivateKeyAsBytes(string data, string privateKey, Encoding encoding = default, SM2Mode mode = SM2Mode.C1C3C2)
        {
            if (privateKey is null || privateKey.Length == 0)
                return null;

            if (data is null || data.Length == 0)
                return null;

            // ReSharper disable once ExpressionIsAlwaysNull
            encoding ??= encoding.SafeValue();

            return DecryptByPrivateKeyAsBytes(encoding.GetBytes(data), privateKey, encoding, mode);
        }

        /// <summary>
        /// Decrypt by private key
        /// </summary>
        /// <param name="dataBytes"></param>
        /// <param name="privateKey"></param>
        /// <param name="encoding"></param>
        /// <param name="mode"></param>
        /// <returns></returns>
        public static byte[] DecryptByPrivateKeyAsBytes(byte[] dataBytes, string privateKey, Encoding encoding = default, SM2Mode mode = SM2Mode.C1C3C2)
        {
            if (privateKey is null || privateKey.Length == 0)
                return null;

            if (dataBytes is null || dataBytes.Length == 0)
                return null;

            // ReSharper disable once ExpressionIsAlwaysNull
            encoding ??= encoding.SafeValue();

            var privateKeyBytes = Hex.Decode(encoding.GetBytes(privateKey));

            var (c1, c2, c3) = GetContent(dataBytes, mode, encoding);

            var sm2 = SM2Core.Instance;
            var userD = new BigInteger(1, privateKeyBytes);

            var c = sm2.ecc_curve.DecodePoint(c1);
            var cipher = new SM2Core.Cipher();
            cipher.Init_dec(userD, c);
            cipher.Decrypt(c2);
            cipher.Dofinal(c3);

            return c2;
        }

        private static (byte[] c1, byte[] c2, byte[] c3) GetContent(byte[] dataBytes, SM2Mode mode, Encoding encoding)
        {
            var data = dataBytes.GetString(encoding);
            var source = Hex.Decode(dataBytes);
            var c2Len = source.Length - 97;
            var c1Offset = 0;
            var c2Offset = mode == SM2Mode.C1C2C3 ? 130 : 130 + 64;
            var c3Offset = mode == SM2Mode.C1C2C3 ? 130 + 2 * c2Len : 130;

            var c1 = Hex.Decode(encoding.GetBytes(data.Substring(c1Offset, 130)));
            var c2 = Hex.Decode(encoding.GetBytes(data.Substring(c2Offset, 2 * c2Len)));
            var c3 = Hex.Decode(encoding.GetBytes(data.Substring(c3Offset, 64)));

            return (c1, c2, c3);
        }
    }
}