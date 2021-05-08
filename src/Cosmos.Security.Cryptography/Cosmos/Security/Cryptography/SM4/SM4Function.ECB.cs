using System;
using System.Threading;
using Cosmos.Security.Cryptography.Core.SymmetricAlgorithmImpls;

namespace Cosmos.Security.Cryptography
{
    internal class SM4ECBFunction: SymmetricCryptoFunction<Sm4Key>, ISM4
    {
        public SM4ECBFunction(Sm4Key key)
        {
            Key = key ?? throw new ArgumentNullException(nameof(key));
        }

        public override Sm4Key Key { get; }

        public override int KeySize => Key.Size;
        
        protected override ICryptoValue EncryptInternal(ArraySegment<byte> originalBytes, CancellationToken cancellationToken)
        {
            var original = GetBytes(originalBytes);
            var ctx = new SM4Context {IsPadding = true, Mode = SM4Core.SM4_ENCRYPT};
            var sm4 = new SM4Core();

            sm4.sm4_setkey_enc(ctx, Key.GetKey());

            var iv = Key.GetIV();
            var cipher = sm4.sm4_crypt_ecb(ctx, original); //ECB MODE

            return CreateCryptoValue(original, cipher, CryptoMode.Encrypt);
        }

        protected override ICryptoValue DecryptInternal(ArraySegment<byte> cipherBytes, CancellationToken cancellationToken)
        {
            var cipher = GetBytes(cipherBytes);
            var ctx = new SM4Context {IsPadding = true, Mode = SM4Core.SM4_DECRYPT};
            var sm4 = new SM4Core();

            sm4.sm4_setkey_dec(ctx, Key.GetKey());

            var iv = Key.GetIV();
            var original = sm4.sm4_crypt_ecb(ctx, cipher);//ECB MODE

            return CreateCryptoValue(original, cipher, CryptoMode.Decrypt);
        }
    }
}