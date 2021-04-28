using System;

// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Verification
{
    public static class MurmurHashFactory
    {
        public static IMurmurHash Create(MurmurHashTypes type)
        {
            return type switch
            {
                MurmurHashTypes.MurmurHash1 => new MurmurHash1Function(new()),
                MurmurHashTypes.MurmurHash2 => new MurmurHash2Function(new()),
                MurmurHashTypes.MurmurHash2Bit32 => new MurmurHash2Function(new() {HashSizeInBits = 32}),
                MurmurHashTypes.MurmurHash2Bit64 => new MurmurHash2Function(new() {HashSizeInBits = 64}),
                MurmurHashTypes.MurmurHash3 => new MurmurHash3Function(new()),
                MurmurHashTypes.MurmurHash3Bit32 => new MurmurHash3Function(new() {HashSizeInBits = 32}),
                MurmurHashTypes.MurmurHash3Bit128 => new MurmurHash3Function(new() {HashSizeInBits = 128}),
                _ => throw new ArgumentOutOfRangeException(nameof(type), type, null)
            };
        }

        public static IMurmurHash MurmurHash1 => new MurmurHash1Function(new());

        public static IMurmurHash Create(MurmurHash1Config config) => new MurmurHash1Function(config);

        public static IMurmurHash Create(Action<MurmurHash1Config> configAct)
        {
            var config = new MurmurHash1Config();
            configAct?.Invoke(config);
            return new MurmurHash1Function(config);
        }

        public static IMurmurHash MurmurHash2 => new MurmurHash2Function(new());

        public static IMurmurHash Create(MurmurHash2Config config) => new MurmurHash2Function(config);

        public static IMurmurHash Create(Action<MurmurHash2Config> configAct)
        {
            var config = new MurmurHash2Config();
            configAct?.Invoke(config);
            return new MurmurHash2Function(config);
        }

        public static IStreamableMurmurHash MurmurHash3 => new MurmurHash3Function(new());

        public static IStreamableMurmurHash Create(MurmurHash3Config config) => new MurmurHash3Function(config);

        public static IStreamableMurmurHash Create(Action<MurmurHash3Config> configAct)
        {
            var config = new MurmurHash3Config();
            configAct?.Invoke(config);
            return new MurmurHash3Function(config);
        }
    }
}