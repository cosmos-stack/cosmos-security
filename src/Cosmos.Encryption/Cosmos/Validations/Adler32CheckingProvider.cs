namespace Cosmos.Validations
{
    /// <summary>
    /// Adler-32 checking provider
    /// </summary>
    public static class Adler32CheckingProvider
    {
        /// <summary>
        /// Compute 
        /// </summary>
        /// <param name="bytesArray">Input data.</param>
        /// <param name="byteStart">The position to begin reading from.</param>
        /// <param name="bytesToRead">How many bytes in the bytesArray to read.</param>
        /// <returns></returns>
        public static uint Compute(byte[] bytesArray, int byteStart, int bytesToRead)
        {
            var adler32 = new Adler32();
            adler32.Update(bytesArray, byteStart, bytesToRead);
            return adler32.Value;
        }
    }
}