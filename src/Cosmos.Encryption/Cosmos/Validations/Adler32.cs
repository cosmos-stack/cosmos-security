using System.IO;

namespace Cosmos.Validations {
    /// <summary>
    /// Adler-32 Checking
    /// </summary>
    public sealed class Adler32 {
        private uint _checkSum = 1;

        /// <summary>
        /// Gets value
        /// </summary>
        public uint Value => _checkSum;

        /// <summary>
        /// Reset
        /// </summary>
        /// <returns></returns>
        public Adler32 Reset() {
            _checkSum = 1;
            return this;
        }

        /// <summary>
        /// Performs the hash algorithm on given data array.
        /// </summary>
        /// <param name="bytesArray">Input data.</param>
        /// <param name="byteStart">The position to begin reading from.</param>
        /// <param name="bytesToRead">How many bytes in the bytesArray to read.</param>
        public Adler32 Update(byte[] bytesArray, int byteStart, int bytesToRead) {
            Checker.Buffer(bytesArray);

            int n;
            uint s1 = _checkSum & 0xFFFF;
            uint s2 = _checkSum >> 16;

            while (bytesToRead > 0) {
                n = (3800 > bytesToRead) ? bytesToRead : 3800;
                bytesToRead -= n;
                while (--n >= 0) {
                    s1 = s1 + (uint) (bytesArray[byteStart++] & 0xFF);
                    s2 = s2 + s1;
                }

                s1 %= 65521;
                s2 %= 65521;
            }

            _checkSum = (s2 << 16) | s1;

            return this;
        }

        /// <summary>
        /// Performs the hash algorithm on given data array.
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="bytesToRead"></param>
        /// <returns></returns>
        public Adler32 Update(Stream stream, int bytesToRead = -1) {
            Checker.Stream(stream);
            return Update(stream.CastToBytes(), 0, bytesToRead);
        }
    }
}