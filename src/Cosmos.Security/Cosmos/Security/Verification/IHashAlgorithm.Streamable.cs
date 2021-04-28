using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Cosmos.Security.Verification
{
    public interface IStreamableHashAlgorithm: IHashAlgorithm
    {
        IHashValue ComputeHash(Stream data);

        IHashValue ComputeHash(Stream data, CancellationToken cancellationToken);

        Task<IHashValue> ComputeHashAsync(Stream data);

        Task<IHashValue> ComputeHashAsync(Stream data, CancellationToken cancellationToken);
    }
}