using Cosmos.Encryption.Symmetric;
using Xunit;

namespace Cosmos.Encryption.Tests.Symmetric
{
    public class XxteaTests
    {
        [Fact]
        public void Encrypt()
        {
            var s = XXTEAEncryptionProvider.Encrypt("AlexLEWIS", "alexinea");
            Assert.Equal("ToAB58U3JHH24EIEWhqSIA==", s);
        }

        [Fact]
        public void Decrypt()
        {
            var o = XXTEAEncryptionProvider.Decrypt("ToAB58U3JHH24EIEWhqSIA==", "alexinea");
            Assert.Equal("AlexLEWIS", o);
        }
    }
}
