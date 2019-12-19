using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

/*
 * Reference to:
 *      https://www.2cto.com/kf/201603/496248.html
 *      https://github.com/myvary/SM2_SM3
 */


// ReSharper disable IdentifierTypo
// ReSharper disable MemberInitializerValueIgnored
// ReSharper disable InconsistentNaming
namespace Cosmos.Encryption.Core {
    internal class SM2 {

        #region 使用标准参数

        public static SM2 Instance => new SM2(false); //返回错

        #endregion

        #region 使用测试参数

        //public static SM2 InstanceTest //返回对
        //{
        //    get
        //    {
        //        return new SM2(true);
        //    }

        //}

        #endregion

        // ReSharper disable once RedundantDefaultMemberInitializer
        public bool sm2Test = false; //初始定义为错

        public string[] ecc_param; // = sm2_test_param;
        public readonly BigInteger ecc_p;
        public readonly BigInteger ecc_a;
        public readonly BigInteger ecc_b;
        public readonly BigInteger ecc_n;
        public readonly BigInteger ecc_gx;
        public readonly BigInteger ecc_gy;

        public readonly ECCurve ecc_curve;   //椭圆曲线的产生字段
        public readonly ECPoint ecc_point_g; //g点坐标的字段

        public readonly ECDomainParameters ecc_bc_spec;

        public readonly ECKeyPairGenerator ecc_key_pair_generator;
        // public ECPoint userKey;
        // public BigInteger userD;

        #region ecc生成

        private SM2(bool sm2Test) {
            this.sm2Test = sm2Test;

            //if (sm2Test)//如果为对
            //    ecc_param = sm2_test_param;//使用国际密码管理局给的测试参数
            //else
            ecc_param = sm2_param; //否则使用国密标准256位曲线参数
            ECFieldElement ecc_gx_fieldelement;
            ECFieldElement ecc_gy_fieldelement;
            ecc_p = new BigInteger(ecc_param[0], 16);
            ecc_a = new BigInteger(ecc_param[1], 16);
            ecc_b = new BigInteger(ecc_param[2], 16);
            ecc_n = new BigInteger(ecc_param[3], 16);
            ecc_gx = new BigInteger(ecc_param[4], 16);
            ecc_gy = new BigInteger(ecc_param[5], 16);
            ecc_gx_fieldelement = new FpFieldElement(ecc_p, ecc_gx);                        //选定椭圆曲线上基点G的x坐标
            ecc_gy_fieldelement = new FpFieldElement(ecc_p, ecc_gy);                        //选定椭圆曲线上基点G的坐标
            ecc_curve = new FpCurve(ecc_p, ecc_a, ecc_b);                                   //生成椭圆曲线
            ecc_point_g = new FpPoint(ecc_curve, ecc_gx_fieldelement, ecc_gy_fieldelement); //生成基点G
            ecc_bc_spec = new ECDomainParameters(ecc_curve, ecc_point_g, ecc_n);            //椭圆曲线，g点坐标，阶n.
            ECKeyGenerationParameters ecc_ecgenparam;
            ecc_ecgenparam = new ECKeyGenerationParameters(ecc_bc_spec, new SecureRandom());
            ecc_key_pair_generator = new ECKeyPairGenerator();
            ecc_key_pair_generator.Init(ecc_ecgenparam);
        }

        #endregion

        #region 计算Z值的方法

        /* SM2签名同样也是需要先摘要原文数据，即先使用SM3密码杂凑算法计算出32byte摘要。SM3需要摘要签名方ID（默认1234567812345678）、
         * 曲线参数a,b,Gx,Gy、共钥坐标(x,y)计算出Z值，然后再杂凑原文得出摘要数据。这个地方要注意曲线参数和坐标点都是32byte，
         * 在转换为BigInteger大数计算转成字节流时要去掉空补位，否则可能会出现摘要计算不正确的问题：*/
        /// <summary>
        /// 计算Z值
        /// </summary>
        /// <param name="userId">签名方ID</param>
        /// <param name="userKey">曲线的各个参数</param>
        /// <returns></returns>
        public virtual byte[] Sm2GetZ(byte[] userId, ECPoint userKey) {
            SM3Digest sm3 = new SM3Digest();
            byte[] p;
            // userId length
            int len = userId.Length * 8; //求userId的长度
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
            p = userKey.XCoord.ToBigInteger().ToByteArray();
            sm3.BlockUpdate(p, 0, p.Length);
            p = userKey.YCoord.ToBigInteger().ToByteArray();
            sm3.BlockUpdate(p, 0, p.Length);

            // Z
            byte[] md = new byte[sm3.GetDigestSize()];
            sm3.DoFinal(md, 0);

            return md;
        }

        #endregion

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
                    if (!sm2Test) //产生随机数k
                    {
                        AsymmetricCipherKeyPair keypair = ecc_key_pair_generator.GenerateKeyPair();
                        ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) keypair.Private; //产生私钥
                        ECPublicKeyParameters ecpub = (ECPublicKeyParameters) keypair.Public;     //产生公钥
                        k = ecpriv.D;                                                             //产生真正的k
                        kp = ecpub.Q;                                                             //kp=生成元
                    }
                    else //如果产生不了则手动添加
                    {
                        string kS = "6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F6CB28D99385C175C94F94E9348176240B";
                        k = new BigInteger(kS, 16);
                        kp = ecc_point_g.Multiply(k);
                    }

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

        public class SM2Result {
            public SM2Result() { }

            // 签名、验签
            public BigInteger r;
            public BigInteger s;
            public BigInteger R;
        }

        #region 国际密码管理局给的测试参数

        //public static readonly string[] sm2_test_param = {
        //    "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3",// p,0
        //    "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498",// a,1
        //    "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A",// b,2
        //    "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7",// n,3
        //    "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D",// gx,4
        //    "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2" // gy,5
        //};

        #endregion

        #region 国密标准256位曲线参数

        public static readonly string[] sm2_param = {
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", // p,0
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", // a,1
            "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", // b,2
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", // n,3
            "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", // gx,4
            "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"  // gy,5
        };

        #endregion

        #region 加密算法类

        public class Cipher {
            private int ct = 1;

            private ECPoint p2;
            private SM3Digest sm3keybase;
            private SM3Digest sm3c3;

            private byte[] key = new byte[32];
            private byte keyOff = 0;

            public Cipher() { }

            private void Reset() {
                sm3keybase = new SM3Digest(); //实例化一个SM3Digest的对象sm3keybase
                sm3c3 = new SM3Digest();      //实例化一个SM3Digest的对象sm3c3

                byte[] p;

                p = p2.XCoord.ToBigInteger().ToByteArray(); //数据类型转化为比特串。
                sm3keybase.BlockUpdate(p, 0, p.Length);     //调用密码杂凑BlockUpdate方法
                sm3c3.BlockUpdate(p, 0, p.Length);          //调用密码杂凑BlockUpdate方法

                p = p2.YCoord.ToBigInteger().ToByteArray(); //数据类型转化为比特串
                sm3keybase.BlockUpdate(p, 0, p.Length);     //调用密码杂凑BlockUpdate方法

                ct = 1;
                NextKey(); //调用NextKey方法
            }

            private void NextKey() {
                SM3Digest sm3keycur = new SM3Digest(sm3keybase);
                sm3keycur.Update((byte) (ct >> 24 & 0x00ff)); //调用密码杂凑Update方法
                sm3keycur.Update((byte) (ct >> 16 & 0x00ff)); //调用密码杂凑Update方法
                sm3keycur.Update((byte) (ct >> 8 & 0x00ff));  //调用密码杂凑Update方法
                sm3keycur.Update((byte) (ct & 0x00ff));
                sm3keycur.DoFinal(key, 0); //调用密码杂凑DoFinal方法
                keyOff = 0;
                ct++;
            }

            public virtual ECPoint Init_enc(SM2 sm2, ECPoint userKey) {
                BigInteger k = null;
                ECPoint c1 = null;
                if (!sm2.sm2Test) //判断使用哪种方法
                {
                    AsymmetricCipherKeyPair key = sm2.ecc_key_pair_generator.GenerateKeyPair();
                    ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) key.Private; //生成私钥
                    ECPublicKeyParameters ecpub = (ECPublicKeyParameters) key.Public;     //生成公钥
                    k = ecpriv.D;                                                         //k
                    c1 = ecpub.Q;                                                         //计算椭圆点c1
                }
                else //使用测试参数
                {
                    k = new BigInteger("4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F", 16); //指定k
                    c1 = sm2.ecc_point_g.Multiply(k);                                                           //获取公钥
                }

                p2 = userKey.Multiply(k);
                Reset(); //调用密码杂凑Reset方法

                return c1; //把公钥返回给调用他得式子.
            }

            public virtual void Encrypt(byte[] data) {
                sm3c3.BlockUpdate(data, 0, data.Length);
                for (int i = 0; i < data.Length; i++) {
                    if (keyOff == key.Length)
                        NextKey();

                    data[i] ^= key[keyOff++];
                }
            }

            public virtual void Init_dec(BigInteger userD, ECPoint c1) {
                p2 = c1.Multiply(userD);
                Reset(); //调用Reset方法
            }

            public virtual void Decrypt(byte[] data) {
                for (int i = 0; i < data.Length; i++) {
                    if (keyOff == key.Length)
                        NextKey();

                    data[i] ^= key[keyOff++];
                }

                sm3c3.BlockUpdate(data, 0, data.Length);
            }

            public virtual void Dofinal(byte[] c3) //密码杂凑中的方法
            {
                byte[] p = p2.YCoord.ToBigInteger().ToByteArray();
                sm3c3.BlockUpdate(p, 0, p.Length);
                sm3c3.DoFinal(c3, 0);
                Reset();
            }
        }

        #endregion

    }
}