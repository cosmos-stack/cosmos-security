using System.IO;
using System.Text;

// ReSharper disable InconsistentNaming

namespace Cosmos.Validations.Abstractions {
    /// <summary>
    /// Interface for CRC
    /// </summary>
    /// <typeparam name="TCRC"></typeparam>
    /// <typeparam name="T1"></typeparam>
    /// <typeparam name="T2"></typeparam>
    public interface ICRC<out TCRC, T1, in T2>
        where TCRC : class, ICRC<TCRC, T1, T2>, new()
        where T1 : struct
        where T2 : struct {
        /// <summary>
        /// Value
        /// </summary>
        T1 Value { get; set; }

        /// <summary>
        /// Reset
        /// </summary>
        /// <returns></returns>
        TCRC Reset();

        /// <summary>
        /// Update
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        TCRC Update(T2 value);

        /// <summary>
        /// Update
        /// </summary>
        /// <param name="value"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        TCRC Update(string value, Encoding encoding = null);

        /// <summary>
        /// Update
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="count"></param>
        /// <returns></returns>
        TCRC Update(byte[] buffer, int offset = 0, long count = -1);

        /// <summary>
        /// Update
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="count"></param>
        /// <returns></returns>
        TCRC Update(Stream stream, long count = -1);
    }
}