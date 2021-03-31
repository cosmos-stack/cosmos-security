using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace Cosmos.Security.Verification.Core
{
    public abstract class BlockTransformerBase<T> : IBlockTransformer
        where T : BlockTransformerBase<T>, new()
    {
        protected const int DefaultCancellationBatchSize = 4096;
        protected const int DefaultInputBlockSize = 1;

        private readonly int _cancellationBatchSize;
        private readonly int _inputBlockSize;

        private byte[] _inputBuffer = null;
        private bool _isCorrupted = false;

        protected BlockTransformerBase(int cancellationBatchSize = DefaultCancellationBatchSize, int inputBlockSize = DefaultInputBlockSize)
        {
            _cancellationBatchSize = cancellationBatchSize;
            _inputBlockSize = inputBlockSize;

            // Ensure _cancellationBatchSize is a multiple of _inputBlockSize, preferrably rounding down.
            {
                var blockSizeRemainder = _cancellationBatchSize % _inputBlockSize;

                if (blockSizeRemainder > 0)
                {
                    _cancellationBatchSize -= blockSizeRemainder;

                    if (_cancellationBatchSize <= 0)
                        _cancellationBatchSize += _inputBlockSize;
                }
            }
        }

        protected byte[] FinalizeInputBuffer => _inputBuffer;

        public void TransformBytes(byte[] data) => TransformBytes(data, CancellationToken.None);

        public void TransformBytes(byte[] data, CancellationToken cancellationToken)
        {
            ThrowIfCorrupted();

            if (data is null)
                throw new ArgumentNullException(nameof(data));

            TransformBytes(data, 0, data.Length, CancellationToken.None);
        }

        public void TransformBytes(byte[] data, int offset, int count)
        {
            TransformBytes(data, 0, data.Length, CancellationToken.None);
        }

        public void TransformBytes(byte[] data, int offset, int count, CancellationToken cancellationToken)
        {
            ThrowIfCorrupted();

            if (data is null)
                throw new ArgumentNullException(nameof(data));

            if (data.Length == 0)
                throw new ArgumentException("data.Length must be greater than 0.", nameof(data));

            if (offset < 0 || offset >= data.Length - 1)
                throw new ArgumentOutOfRangeException(nameof(offset), "Offset must be a value greater than or equal to zero and less than the length of the array minus one.");

            if (count <= 0 || count > data.Length - offset)
                throw new ArgumentOutOfRangeException(nameof(count), "Count must be a value greater than zero and less than the the remaining length of the array after the offset value.");


            TransformBytes(new ArraySegment<byte>(data, offset, count), cancellationToken);
        }

        public void TransformBytes(ArraySegment<byte> data) => TransformBytes(data, CancellationToken.None);

        public void TransformBytes(ArraySegment<byte> data, CancellationToken cancellationToken)
        {
            if (data.Count == 0)
                throw new ArgumentException("data must be an ArraySegment of Count > 0.", nameof(data));

            TransformBytesInternal(data, cancellationToken);
        }

        public IHashValue FinalizeHashValue() => FinalizeHashValue(CancellationToken.None);

        public IHashValue FinalizeHashValue(CancellationToken cancellationToken)
        {
            ThrowIfCorrupted();

            return FinalizeHashValueInternal(cancellationToken);
        }

        public IBlockTransformer Clone()
        {
            ThrowIfCorrupted();

            var clone = new T();

            CopyStateTo(clone);

            return clone;
        }

        protected virtual void CopyStateTo(T other)
        {
            other._inputBuffer = _inputBuffer;
        }

        protected void ThrowIfCorrupted()
        {
            if (_isCorrupted)
                throw new InvalidOperationException("A previous transformation cancellation has resulted in an undefined internal state.");
        }

        protected void MarkSelfCorrupted()
        {
            _isCorrupted = true;
        }

        protected void TransformBytesInternal(ArraySegment<byte> data, CancellationToken cancellationToken)
        {
            var dataArray = data.Array;
            var dataCurrentOffset = data.Offset;
            var dataRemainingCount = data.Count;

            var totalBytesToProcess = (_inputBuffer?.Length).GetValueOrDefault() + dataRemainingCount;
            var processingRemainder = totalBytesToProcess % _inputBlockSize;

            // Determine how many bytes will inevitably be rolled over into the next input buffer and prepare that buffer.
            byte[] nextInputBuffer = null;
            {
                if (processingRemainder > 0)
                {
                    nextInputBuffer = new byte[processingRemainder];

                    if (dataRemainingCount >= processingRemainder)
                    {
                        // All of the data can be fetched from newest data
                        var copyFromOffset = dataCurrentOffset + dataRemainingCount - processingRemainder;

                        Array.Copy(dataArray, copyFromOffset, nextInputBuffer, 0, processingRemainder);

                        dataRemainingCount -= processingRemainder;
                    }
                    else
                    {
                        var bytesRolledOver = 0;

                        if (_inputBuffer != null)
                        {
                            Array.Copy(_inputBuffer, nextInputBuffer, _inputBuffer.Length);

                            bytesRolledOver = _inputBuffer.Length;
                        }

                        Array.Copy(dataArray, 0, nextInputBuffer, bytesRolledOver, processingRemainder - bytesRolledOver);

                        dataRemainingCount = 0;
                    }
                }
            }

            // Process the full groups available
            if (dataRemainingCount > 0)
            {
                try
                {
                    if (_inputBuffer != null)
                    {
                        var overrideInputBuffer = new byte[_inputBlockSize];
                        var dataBytesToRead = overrideInputBuffer.Length - _inputBuffer.Length;

                        Array.Copy(_inputBuffer, overrideInputBuffer, _inputBuffer.Length);
                        Array.Copy(dataArray, dataCurrentOffset, overrideInputBuffer, _inputBuffer.Length, dataBytesToRead);

                        dataCurrentOffset += dataBytesToRead;
                        dataRemainingCount -= dataBytesToRead;


                        TransformByteGroupsInternal(new ArraySegment<byte>(overrideInputBuffer, 0, overrideInputBuffer.Length));
                    }

                    while (dataRemainingCount > 0)
                    {
                        cancellationToken.ThrowIfCancellationRequested();

                        var bytesToProcess = Math.Min(dataRemainingCount, _cancellationBatchSize);

                        TransformByteGroupsInternal(new ArraySegment<byte>(data.Array, dataCurrentOffset, bytesToProcess));

                        dataCurrentOffset += bytesToProcess;
                        dataRemainingCount -= bytesToProcess;
                    }

                    Debug.Assert(dataRemainingCount == 0);
                }
                catch (TaskCanceledException)
                {
                    MarkSelfCorrupted();

                    throw;
                }
            }

            // Update input buffer
            _inputBuffer = nextInputBuffer;
        }

        protected abstract void TransformByteGroupsInternal(ArraySegment<byte> data);

        protected abstract IHashValue FinalizeHashValueInternal(CancellationToken cancellationToken);
    }
}