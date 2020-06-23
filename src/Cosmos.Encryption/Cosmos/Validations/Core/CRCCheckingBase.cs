using System.IO;
using Cosmos.Validations.Abstractions;

namespace Cosmos.Validations.Core
{
    /// <summary>
    /// CRCCheckingBase
    /// </summary>
    /// <typeparam name="T1"></typeparam>
    /// <typeparam name="T2"></typeparam>
    // ReSharper disable InconsistentNaming
    public abstract class CRCCheckingBase<T1, T2>
    where T1 : struct
    where T2 : struct
    {
        /// <summary>
        /// Compute
        /// </summary>
        /// <param name="buf"></param>
        /// <param name="offset"></param>
        /// <param name="count"></param>
        /// <typeparam name="TCRC"></typeparam>
        /// <returns></returns>
        protected static T1 Compute<TCRC>(byte[] buf, int offset = 0, int count = -1)
        where TCRC : class, ICRC<TCRC, T1, T2>, new()
        {
            var crc = new TCRC();
            crc.Update(buf, offset, count);
            return crc.Value;
        }

        /// <summary>
        /// Compute
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="count"></param>
        /// <typeparam name="TCRC"></typeparam>
        /// <returns></returns>
        protected static T1 Compute<TCRC>(Stream stream, int count = -1)
        where TCRC : class, ICRC<TCRC, T1, T2>, new()
        {
            var crc = new TCRC();
            crc.Update(stream, count);
            return crc.Value;
        }

        /// <summary>
        /// Compute
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="position"></param>
        /// <param name="count"></param>
        /// <typeparam name="TCRC"></typeparam>
        /// <returns></returns>
        protected static T1 Compute<TCRC>(Stream stream, long position = -1, int count = -1)
        where TCRC : class, ICRC<TCRC, T1, T2>, new()
        {
            if (position >= 0)
            {
                if (count > 0) count = -count;
                count += (int) (stream.Position - position);
                if (count == 0) return default;
                stream.Position = position;
            }

            var crc = new TCRC();
            crc.Update(stream, count);
            return crc.Value;
        }
    }
}