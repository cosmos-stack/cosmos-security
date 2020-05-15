using Xunit;

namespace Cosmos.Encryption.Tests.Symmetric {
    public class RcyTests {
        [Fact]
        public void Encrypt() {
            var s = RCYEncryptionProvider.Encrypt("ABCDDDDDDDDDDDDDDDDDDDDDD", "alexinea");
            Assert.Equal("QCMiN9UlyMhNypE52bTzJaAlFAdFddB1mw==", s);
        }

        [Fact]
        public void Encrypt_ThreeRCY() {
            var s = ThreeRCYEncryptionProvider.Encrypt("ABCDDDDDDDDDDDDDDDDDDDDDD", "alexinea");
            Assert.Equal("SHNK5w4Qc42CRf6YoE3V4JvZMtObzUWgRQ==", s);
        }

        [Fact]
        public void Decrypt() {
            var o = RCYEncryptionProvider.Decrypt("QCMiN9UlyMhNypE52bTzJaAlFAdFddB1mw==", "alexinea");
            Assert.Equal("ABCDDDDDDDDDDDDDDDDDDDDDD", o);
        }

        [Fact]
        public void Decrypt_ThreeRCY() {
            var o = ThreeRCYEncryptionProvider.Decrypt("SHNK5w4Qc42CRf6YoE3V4JvZMtObzUWgRQ==", "alexinea");
            Assert.Equal("ABCDDDDDDDDDDDDDDDDDDDDDD", o);
        }
    }
}