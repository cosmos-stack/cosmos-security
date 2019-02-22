using System;
using System.Collections.Generic;
using System.Text;
using Cosmos.Encryption.Symmetric;
using Xunit;

namespace Cosmos.Encryption.Tests.Symmetric
{
    public class XxteaTests
    {
        [Fact]
        public void XXTEATest()
        {
            var s = XXTEAEncryptionProvider.Encrypt("AlexLEWIS", "alexinea");
            var o = XXTEAEncryptionProvider.Decrypt(s, "alexinea");
            Assert.Equal("AlexLEWIS", o);
        }

        [Fact]
        public void XTEATest()
        {
            var s = XTEAEncryptionProvider.Encrypt("AlexLEWISAlexLEWISAlexLEWISAlexLEWISAlexLEWISAlexLEWISAlexLEWIS", "alexineaalexinea");
            var o = XTEAEncryptionProvider.Decrypt(s, "alexineaalexinea");
            Assert.Equal("AlexLEWISAlexLEWISAlexLEWISAlexLEWISAlexLEWISAlexLEWISAlexLEWIS", o);
        }

        [Fact]
        public void TEATest()
        {
            var s = TEAEncryptionProvider.Encrypt("AlexLEWIS", "alexinea");
            var o = TEAEncryptionProvider.Decrypt(s, "alexinea");
            Assert.Equal("AlexLEWIS", o);
        }
    }
}
