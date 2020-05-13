using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;

namespace Cosmos.Encryption.Core {
    // ReSharper disable once InconsistentNaming
    internal partial class SM2Core {
        public virtual byte[] Sm2GetZ(byte[] userId, ECPoint userKey) {
            SM2_SM3Digest sm3 = new SM2_SM3Digest();
            byte[] p;
            // userId length
            int len = userId.Length * 8;
            sm3.Update((byte) (len >> 8 & 0x00ff));
            sm3.Update((byte) (len & 0x00ff));

            // userId
            sm3.BlockUpdate(userId, 0, userId.Length);

            // a,b
            p = ecc_a.ToByteArray();
            sm3.BlockUpdate(p, 0, p.Length);
            p = ecc_b.ToByteArray();
            sm3.BlockUpdate(p, 0, p.Length);
            // gx,gy
            p = ecc_gx.ToByteArray();
            sm3.BlockUpdate(p, 0, p.Length);
            p = ecc_gy.ToByteArray();
            sm3.BlockUpdate(p, 0, p.Length);

            // x,y
            p = userKey.AffineXCoord.ToBigInteger().ToByteArray();
            sm3.BlockUpdate(p, 0, p.Length);
            p = userKey.AffineYCoord.ToBigInteger().ToByteArray();
            sm3.BlockUpdate(p, 0, p.Length);

            // Z
            byte[] md = new byte[sm3.GetDigestSize()];
            sm3.DoFinal(md, 0);

            return md;
        }

        #region 数字签名，生成s,r;

        /*
         * SM2算法是基于ECC算法的，签名同样返回2个大数，共64byte。由于原来RSA算法已很普遍支持，
         * 要实现RSA的签名验签都有标准库的实现，而SM2是国密算法在国际上还没有标准通用，算法Oid标识在X509标准中是没定义的。
         * 在.Net或Java中可以基于使用BouncyCastle加密库实现，开源的也比较好学习扩展。SM2算法验签可以使用软验签，
         * 即可以不需要使用硬件设备，同样使用原始数据、签名、证书(公钥)来实现对签名方验证，保证数据完整性未被篡改。
         * 验证过程同样需先摘要原文数据，公钥在证书中是以一个66byte的BitString，去掉前面标记位即64byte为共钥坐标(x,y)，
         * 中间分割截取再以Hex方式转成BigInteger大数计算，验签代码如下：
         */
        /// <summary>
        /// 
        /// </summary>
        /// <param name="md">消息</param>
        /// <param name="userD">秘钥</param>
        /// <param name="userKey">公钥</param>
        /// <param name="sm2Ret">sm2Ret集合</param>
        public virtual void Sm2Sign(byte[] md, BigInteger userD, ECPoint userKey, SM2Result sm2Ret) {
            // e
            BigInteger e = new BigInteger(1, md); //字节转化大整数
            // k
            BigInteger k; //初始定义大数k为空
            ECPoint kp;   //定义kp点为空
            BigInteger r; //定义大数r为空，保存求得的r值
            BigInteger s; //定义大数r为空，保存求得的s值

            do {
                do {
                    AsymmetricCipherKeyPair keypair = ecc_key_pair_generator.GenerateKeyPair();
                    ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) keypair.Private; //产生私钥
                    ECPublicKeyParameters ecpub = (ECPublicKeyParameters) keypair.Public;     //产生公钥
                    k = ecpriv.D;                                                             //产生真正的k
                    kp = ecpub.Q;

                    // r
                    r = e.Add(kp.XCoord.ToBigInteger());                       //r=e+kp坐标点的X
                    r = r.Mod(ecc_n);                                          //对r进行模n运算，防止越界
                } while (r.Equals(BigInteger.Zero) || r.Add(k).Equals(ecc_n)); //r==或者0当r==n时跳出循环

                // (1 + dA)~-1
                BigInteger da_1 = userD.Add(BigInteger.One); //da_1=秘钥+1;
                da_1 = da_1.ModInverse(ecc_n);               //对da_1求逆运算
                // s
                s = r.Multiply(userD);           //s=r*秘钥
                s = k.Subtract(s).Mod(ecc_n);    //s=((k-s)%n);
                s = da_1.Multiply(s).Mod(ecc_n); //s=((da_1*s)%n)
            } while (s.Equals(BigInteger.Zero)); //s==0的时候跳出循环

            sm2Ret.r = r;
            sm2Ret.s = s;
        }

        #endregion

        #region 验证

        /// <summary>
        /// 
        /// </summary>
        /// <param name="md">消息</param>
        /// <param name="userKey">公钥</param>
        /// <param name="r">由数字签名得到的大数r</param>
        /// <param name="s">由数字签名得到的大数s</param>
        /// <param name="sm2Ret"></param>
        public virtual void Sm2Verify(byte[] md, ECPoint userKey, BigInteger r, BigInteger s, SM2Result sm2Ret) //客户端验证
        {
            sm2Ret.R = null;

            // e_
            BigInteger e = new BigInteger(1, md); //字节转化大整数e
            // t
            BigInteger t = r.Add(s).Mod(ecc_n); //大数t=(r+s)%n;

            if (t.Equals(BigInteger.Zero)) //如果t==0，返回上一层
                return;

            // x1y1
            ECPoint x1y1 = ecc_point_g.Multiply(sm2Ret.s); //x1y1=g*s
            x1y1 = x1y1.Add(userKey.Multiply(t));          //x1y1=x1y1+公钥*(t),其中t=(r+s)%n

            // R
            sm2Ret.R = e.Add(x1y1.XCoord.ToBigInteger()).Mod(ecc_n); //r=(x1y1点的X的大数形式+e)%n
        }

        #endregion

    }
}