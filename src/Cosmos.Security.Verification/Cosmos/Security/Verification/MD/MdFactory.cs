using System;

// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Verification
{
    /// <summary>
    /// Message Digest Hash Function Factory
    /// </summary>
    public static class MdFactory
    {
        public static IMD Create(MdTypes type = MdTypes.Md5) => new MdFunction(type);

        public static IMD Create(Md6Options options) => new MdFunction(options);

        public static IMD Create(Action<Md6Options> optionsAct)
        {
            var options = Md6Options.Md6Bit256();
            optionsAct?.Invoke(options);
            return Create(options);
        }

        public static IMD Md2 => Create(MdTypes.Md2);
        public static IMD Md4 => Create(MdTypes.Md4);
        public static IMD Md5 => Create(MdTypes.Md5);
        public static IMD Md6 => Create(MdTypes.Md6);
    }
}