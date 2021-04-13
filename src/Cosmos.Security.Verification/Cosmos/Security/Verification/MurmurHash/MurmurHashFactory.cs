using System;
// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Verification
{
    public static class MurmurHashFactory
    {
        public static IHashFunction Create(MurmurHashTypes type)
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

        public static MurmurHash1Function MurmurHash1 => new MurmurHash1Function(new());

        public static MurmurHash1Function Create(MurmurHash1Config config) => new(config);

        public static MurmurHash1Function Create(Action<MurmurHash1Config> configAct)
        {
            var config = new MurmurHash1Config();
            configAct?.Invoke(config);
            return new(config);
        }

        public static MurmurHash2Function MurmurHash2 => new MurmurHash2Function(new());

        public static MurmurHash2Function Create(MurmurHash2Config config) => new(config);

        public static MurmurHash2Function Create(Action<MurmurHash2Config> configAct)
        {
            var config = new MurmurHash2Config();
            configAct?.Invoke(config);
            return new(config);
        }

        public static MurmurHash3Function MurmurHash3 => new MurmurHash3Function(new());

        public static MurmurHash3Function Create(MurmurHash3Config config) => new(config);

        public static MurmurHash3Function Create(Action<MurmurHash3Config> configAct)
        {
            var config = new MurmurHash3Config();
            configAct?.Invoke(config);
            return new(config);
        }
    }
}