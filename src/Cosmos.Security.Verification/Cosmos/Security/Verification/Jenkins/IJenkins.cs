namespace Cosmos.Security.Verification
{
    public interface IJenkins : IHashAlgorithm { }

    public interface IStreamableJenkins : IJenkins, IStreamableHashAlgorithm, IHashAlgorithm { }
}