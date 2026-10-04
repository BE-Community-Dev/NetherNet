using System.Security.Cryptography;
using SIPSorcery.Net;

namespace NetherNet;

public interface INegotiator
{
    void HandleClose(Conn conn);
}

public sealed class Conn : IDisposable
{
    internal const int MaxMessageSize = 262143;

    internal RTCPeerConnection Peer;
    internal Description LocalDescription = new();
    internal ECDsa? PublicKey;
    internal ulong Id;
    internal string NetworkID = "";
    internal string LocalNetworkID = "";
    internal INegotiator? Negotiator;

    private readonly NetherDataChannel?[] _channels = new NetherDataChannel?[MessageReliabilityExtensions.Capacity];
    private readonly ReaderWriterLockSlim _channelsLock = new();
    private uint _maxSegmentPayload = MaxMessageSize;

    private readonly SemaphoreSlim _readLock = new(1, 1);
    private List<byte> _readBuf = new();

    private readonly CancellationTokenSource _cts = new();
    private Exception? _cause;
    private int _closed;

    internal readonly TaskCompletionSource CandidateReceived = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly List<IceCandidate> _remoteCandidates = new();
    private readonly List<IceCandidate> _localCandidates = new();
    private readonly object _candidatesLock = new();

    internal Conn(RTCPeerConnection peer, ulong id, string networkID, string localNetworkID, INegotiator? negotiator)
    {
        Peer = peer;
        Id = id;
        NetworkID = networkID;
        LocalNetworkID = localNetworkID;
        Negotiator = negotiator;
    }

    public CancellationToken Context => _cts.Token;

    public Exception? ContextCause => _cause;

    public ECDsa? PublicKeyOrNull => PublicKey;

    public bool IsClosed => Volatile.Read(ref _closed) != 0;

    public int Read(byte[] b)
    {
        _readLock.Wait();
        try
        {
            if (_readBuf.Count == 0)
            {
                var pk = ReceiveAsync(MessageReliability.Reliable).GetAwaiter().GetResult();
                _readBuf = new List<byte>(pk);
            }
            var n = Math.Min(b.Length, _readBuf.Count);
            _readBuf.CopyTo(0, b, 0, n);
            _readBuf.RemoveRange(0, n);
            if (_readBuf.Count == 0) _readBuf.Clear();
            return n;
        }
        finally
        {
            _readLock.Release();
        }
    }

    public async Task<byte[]> ReceiveAsync(MessageReliability r, CancellationToken ctx = default)
    {
        if ((byte)r >= MessageReliabilityExtensions.Capacity)
            throw new NetherNetException($"invalid message reliability: {(byte)r}");

        var channel = Channel(r) ?? throw new NetherNetException($"nethernet: data channel {r.Label()} is not available");
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token, ctx);
        try
        {
            return await channel.Packets.ReadAsync(linked.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (_cts.IsCancellationRequested)
        {
            throw new NetherNetException("nethernet: connection is closed", _cause);
        }
    }

    public byte[] Receive(MessageReliability r) => ReceiveAsync(r).GetAwaiter().GetResult();

    public byte[] ReadPacket() => ReceiveAsync(MessageReliability.Reliable).GetAwaiter().GetResult();

    public int Write(byte[] b) => Send(b, MessageReliability.Reliable);

    public int Send(byte[] data, MessageReliability reliability)
    {
        if (_cts.IsCancellationRequested)
            throw ClosedWriteError(_cause);

        if ((byte)reliability >= MessageReliabilityExtensions.Capacity)
            throw new NetherNetException($"invalid message reliability: {(byte)reliability}");

        var segmentSize = (int)_maxSegmentPayload;
        if (segmentSize == 0) segmentSize = MaxMessageSize;

        if (reliability == MessageReliability.Unreliable && data.Length > segmentSize)
            throw new NetherNetException($"data larger than {segmentSize} (received: {data.Length}) cannot be sent over UnreliableDataChannel");

        var d = Channel(reliability) ?? throw new NetherNetException($"nethernet: data channel {reliability.Label()} is not available");

        var totalSegments = data.Length == 0 ? 0 : (data.Length - 1) / segmentSize + 1;
        if (totalSegments > byte.MaxValue)
            throw new NetherNetException($"data too large: {data.Length} bytes requires {totalSegments} segments (max {byte.MaxValue})");

        var remaining = totalSegments - 1;
        var n = 0;
        for (var i = 0; i < data.Length; i += segmentSize)
        {
            var len = Math.Min(segmentSize, data.Length - i);
            var frag = new byte[1 + len];
            frag[0] = (byte)remaining;
            Array.Copy(data, i, frag, 1, len);
            try
            {
                d.Send(frag);
            }
            catch (Exception e)
            {
                throw new NetherNetException($"write segment #{totalSegments - 1 - remaining}", ClosedWriteError(e));
            }
            n += len;
            remaining--;
        }
        return n;
    }

    private static Exception ClosedWriteError(Exception? cause)
        => cause ?? new NetherNetException("nethernet: connection is closed");

    public TimeSpan Latency => TimeSpan.Zero;

    public Addr LocalAddr()
    {
        var addr = new Addr
        {
            NetworkID = LocalNetworkID,
            ConnectionID = Id,
        };
        lock (_candidatesLock)
        {
            addr.Candidates = new List<IceCandidate>(_localCandidates);
        }
        return addr;
    }

    public Addr RemoteAddr()
    {
        var addr = new Addr
        {
            NetworkID = NetworkID,
            ConnectionID = Id,
        };
        lock (_candidatesLock)
        {
            addr.Candidates = new List<IceCandidate>(_remoteCandidates);
        }
        return addr;
    }

    internal void SetLocalCandidates(IEnumerable<IceCandidate> candidates)
    {
        lock (_candidatesLock)
        {
            _localCandidates.Clear();
            _localCandidates.AddRange(candidates);
        }
    }

    internal void SetMaxSegmentPayload(uint value) => _maxSegmentPayload = value;

    internal void AttachDataChannel(RTCDataChannel channel, MessageReliability reliability)
    {
        var wrapped = new NetherDataChannel(channel, reliability);
        channel.onmessage += (_, _, data) =>
        {
            try
            {
                wrapped.HandleMessage(data);
            }
            catch (Exception e)
            {
                _ = Task.Run(() => Close(new NetherNetException($"nethernet: handle message in {reliability.Label()}", e)));
            }
        };
        channel.onclose += () => _ = Task.Run(() => Close(new NetherNetException($"nethernet: data channel \"{reliability.Label()}\" closed by remote peer")));

        if (StoreChannel(reliability, wrapped) is not null)
            _ = Task.Run(() => Close(new NetherNetException($"nethernet: data channel created for same reliability parameters: \"{reliability.Label()}\"")));
    }

    internal NetherDataChannel? Channel(MessageReliability r)
    {
        _channelsLock.EnterReadLock();
        try
        {
            return _channels[(byte)r];
        }
        finally
        {
            _channelsLock.ExitReadLock();
        }
    }

    internal NetherDataChannel? StoreChannel(MessageReliability r, NetherDataChannel ch)
    {
        _channelsLock.EnterWriteLock();
        try
        {
            var existing = _channels[(byte)r];
            if (existing is null) _channels[(byte)r] = ch;
            return existing;
        }
        finally
        {
            _channelsLock.ExitWriteLock();
        }
    }

    private NetherDataChannel?[] SnapshotChannels()
    {
        _channelsLock.EnterReadLock();
        try
        {
            return (NetherDataChannel?[])_channels.Clone();
        }
        finally
        {
            _channelsLock.ExitReadLock();
        }
    }

    internal void HandleSignal(Signal signal)
    {
        if (_cts.IsCancellationRequested)
            throw new NetherNetException("nethernet: connection is closed", _cause);

        switch (signal.Type)
        {
            case SignalType.Candidate:
                AddRemoteCandidate(signal.Data);
                break;
            case SignalType.Error:
                var code = Signal.ParseSignalErrorCode(signal.Data);
                var cause = new NetherNetException($"nethernet: remote peer notified connection failure (code: {code})");
                Close(cause);
                break;
            default:
                throw new NetherNetException($"unknown signal type: {signal.Type}");
        }
    }

    internal void AddRemoteCandidate(string raw)
    {
        var candidate = IceCandidateParser.ParseRemoteCandidate(raw);
        var normalized = NormalizeCandidateString(raw);
        try
        {
            Peer.addIceCandidate(new RTCIceCandidateInit
            {
                candidate = normalized,
                sdpMid = "0",
                sdpMLineIndex = 0,
            });
        }
        catch (Exception e)
        {
            throw new NetherNetException("add remote candidate", e);
        }

        lock (_candidatesLock)
        {
            if (_remoteCandidates.Count == 0) CandidateReceived.TrySetResult();
            _remoteCandidates.Add(candidate);
        }
    }

    private static string NormalizeCandidateString(string raw)
    {
        var s = raw.Trim();
        if (s.StartsWith("a=", StringComparison.Ordinal)) s = s[2..];
        if (!s.StartsWith("candidate:", StringComparison.Ordinal)) s = "candidate:" + s;
        return s;
    }

    public void Close() => Close(null);

    internal void Close(Exception? cause)
    {
        if (Interlocked.Exchange(ref _closed, 1) != 0) return;
        _cause = cause;
        try
        {
            _cts.Cancel();
        }
        catch (Exception)
        {
            // ignored.
        }
        Negotiator?.HandleClose(this);

        foreach (var ch in SnapshotChannels())
        {
            ch?.Close();
        }

        try
        {
            Peer.close();
        }
        catch (Exception)
        {
            // ignored.
        }
    }

    public void Dispose()
    {
        Close();
        _cts.Dispose();
        _readLock.Dispose();
    }
}