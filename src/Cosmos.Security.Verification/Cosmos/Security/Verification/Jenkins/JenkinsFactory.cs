using Cosmos.Security.Verification.Core;

// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Verification
{
    /// <summary>
    /// Jenkins Hash Function Factory
    /// </summary>
    public class JenkinsFactory
    {
        public static HashFunctionBase Create(JenkinsTypes type = JenkinsTypes.OneAtTime)
        {
            return Create(type, new JenkinsConfig());
        }

        public static HashFunctionBase Create(JenkinsTypes type, JenkinsConfig config)
        {
            if (type is not JenkinsTypes.OneAtTime)
            {
                config.CheckNull(nameof(config));
                config = config.Clone();

                config.HashSizeInBits = type switch
                {
                    JenkinsTypes.Lookup2 => 32,
                    JenkinsTypes.Lookup3Bit32 => 32,
                    JenkinsTypes.Lookup3Bit64 => 64,
                    _ => 32
                };
            }

            return type switch
            {
                JenkinsTypes.Lookup2 => new JenkinsLookup2Function(config),
                JenkinsTypes.Lookup3Bit32 => new JenkinsLookup3Function(config),
                JenkinsTypes.Lookup3Bit64 => new JenkinsLookup3Function(config),
                JenkinsTypes.OneAtTime => new JenkinsOneAtTimeFunction(),
                _ => new JenkinsOneAtTimeFunction()
            };
        }
    }
}