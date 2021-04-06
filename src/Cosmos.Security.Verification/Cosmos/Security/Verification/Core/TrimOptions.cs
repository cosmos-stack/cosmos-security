namespace Cosmos.Security.Verification.Core
{
    /// <summary>
    /// The entry used to trim the result of the Hash operation.
    /// </summary>
    internal class TrimOptions
    {
        /// <summary>
        /// 跳过强制转换
        /// </summary>
        public bool SkipForceConvert { get; set; }

        /// <summary>
        /// 十六进制数，输出时移除首位的 0，默认为 false
        /// </summary>
        public bool HexTrimLeadingZeroAsDefault { get; set; }

        public static TrimOptions Instance { get; } = new();
    }
}