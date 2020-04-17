using System;
using System.IO;

namespace Cosmos {
    internal static class Checker {
        public static void Data(string data) {
            if (string.IsNullOrEmpty(data)) {
                throw new ArgumentNullException(nameof(data));
            }
        }

        public static void Password(string pwd) {
            if (string.IsNullOrEmpty(pwd)) {
                throw new ArgumentNullException(nameof(pwd));
            }
        }

        public static void IV(string iv) {
            if (string.IsNullOrEmpty(iv)) {
                throw new ArgumentNullException(nameof(iv));
            }
        }

        public static void Key<T>(T key) where T : class {
            if (key is string strKey) {
                if (string.IsNullOrEmpty(strKey))
                    throw new ArgumentNullException(nameof(key));
            }

            if (key == default(T)) {
                throw new ArgumentNullException(nameof(key));
            }
        }

        public static void Buffer(byte[] buffer) {
            if (buffer == null) {
                throw new ArgumentNullException(nameof(buffer));
            }
        }

        public static void Stream(Stream stream) {
            if (stream == null) {
                throw new ArgumentNullException(nameof(stream));
            }
        }

        public static void File(string filePath, string nameOfFilePath = null) {
            nameOfFilePath = string.IsNullOrEmpty(nameOfFilePath) ? nameof(filePath) : nameOfFilePath;
            if (!System.IO.File.Exists(filePath)) {
                throw new FileNotFoundException(nameOfFilePath);
            }
        }
    }
}