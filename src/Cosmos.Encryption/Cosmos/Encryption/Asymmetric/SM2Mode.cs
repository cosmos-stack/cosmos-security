namespace Cosmos.Encryption.Asymmetric
{
    /// <summary>
    /// SM2 Mode
    /// </summary>
    // ReSharper disable once InconsistentNaming
    public enum SM2Mode
    {
        /// <summary>
        /// 旧标准的为C1C2C3
        /// </summary>
        C1C2C3,

        /// <summary>
        /// 新的[《SM2密码算法使用规范》 GM/T 0009-2012]标准为C1C3C2
        /// </summary>
        C1C3C2
    }
}