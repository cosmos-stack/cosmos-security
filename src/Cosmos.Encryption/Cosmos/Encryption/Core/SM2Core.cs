using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Cosmos.Encryption.Core {
    // ReSharper disable once InconsistentNaming
    internal partial class SM2Core {
        public static SM2Core Instance => new SM2Core();

        public static readonly string[] sm2_param = {
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", // p,0
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", // a,1
            "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", // b,2
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", // n,3
            "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", // gx,4
            "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"  // gy,5
        };

        public string[] ecc_param = sm2_param;

        public readonly BigInteger ecc_p;
        public readonly BigInteger ecc_a;
        public readonly BigInteger ecc_b;
        public readonly BigInteger ecc_n;
        public readonly BigInteger ecc_gx;
        public readonly BigInteger ecc_gy;

        public readonly ECCurve ecc_curve;
        public readonly ECPoint ecc_point_g;

        public readonly ECDomainParameters ecc_bc_spec;

        public readonly ECKeyPairGenerator ecc_key_pair_generator;

        private SM2Core() {
            ecc_param = sm2_param;

            ECFieldElement ecc_gx_fieldelement;
            ECFieldElement ecc_gy_fieldelement;

            ecc_p = new BigInteger(ecc_param[0], 16);
            ecc_a = new BigInteger(ecc_param[1], 16);
            ecc_b = new BigInteger(ecc_param[2], 16);
            ecc_n = new BigInteger(ecc_param[3], 16);
            ecc_gx = new BigInteger(ecc_param[4], 16);
            ecc_gy = new BigInteger(ecc_param[5], 16);


            ecc_gx_fieldelement = new FpFieldElement(ecc_p, ecc_gx);
            ecc_gy_fieldelement = new FpFieldElement(ecc_p, ecc_gy);

            ecc_curve = new FpCurve(ecc_p, ecc_a, ecc_b);
            ecc_point_g = new FpPoint(ecc_curve, ecc_gx_fieldelement, ecc_gy_fieldelement);

            ecc_bc_spec = new ECDomainParameters(ecc_curve, ecc_point_g, ecc_n);

            ECKeyGenerationParameters ecc_ecgenparam;
            ecc_ecgenparam = new ECKeyGenerationParameters(ecc_bc_spec, new SecureRandom());

            ecc_key_pair_generator = new ECKeyPairGenerator();
            ecc_key_pair_generator.Init(ecc_ecgenparam);
        }
    }
}