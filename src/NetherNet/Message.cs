using System.Threading.Channels;
using SIPSorcery.Net;

namespace NetherNet;

public enum MessageReliability : byte
{
    Reliable = 0,
    Unreliable = 1,
}

public static class MessageReliabilityExtensions
{
    public const int Capacity = 2;

    public static RTCDataChannelInit Parameters(this MessageReliability r) => r switch
    {
        MessageReliability.Reliable => new RTCDataChannelInit { ordered = true },
        MessageReliability.Unreliable => new RTCDataChannelInit { ordered = false, maxRetransmits = 1 },
        _ => throw new NetherNetException($"nethernet: MessageReliability.Parameters: unknown value: {(byte)r}"),
    };

    public static string Label(this MessageReliability r) => r switch
    {
        MessageReliability.Reliable => "ReliableDataChannel",
        MessageReliability.Unreliable => "UnreliableDataChannel",
        _ => throw new NetherNetException($"nethernet: MessageReliability: unknown value: {(byte)r}"),
    };

    public static bool Valid(this MessageReliability r, RTCDataChannel channel)
    {
        if ((channel.label ?? "") != r.Label())
            return false;
        if ((channel.protocol ?? "") != (r.Parameters().protocol ?? ""))
            return false;
        if (channel.negotiated != (r.Parameters().negotiated ?? false))
            return false;
        if (r == MessageReliability.Reliable && !channel.ordered)
            return false;
        return true;
    }
}

public sealed class Message
{
    public byte Segments;
    public List<byte> Data = new();
}

public sealed class NetherDataChannel
{
    private readonly RTCDataChannel _channel;
    private readonly MessageReliability _reliability;
    private readonly Message _message = new();
    private readonly object _messageLock = new();
    private readonly Channel<byte[]> _packets = System.Threading.Channels.Channel.CreateUnbounded<byte[]>();
    private int _closed;

    public NetherDataChannel(RTCDataChannel channel, MessageReliability reliability)
    {
        _channel = channel;
        _reliability = reliability;
    }

    public RTCDataChannel Channel => _channel;

    public ChannelReader<byte[]> Packets => _packets.Reader;

    public bool IsClosed => Volatile.Read(ref _closed) != 0;

    public void HandleMessage(byte[] b)
    {
        if (IsClosed) throw new NetherNetException("nethernet: data channel is closed");

        var msg = ParseMessage(b);
        if (_reliability == MessageReliability.Unreliable && msg.Segments > 0)
            throw new NetherNetException($"unexpected segment count on UnreliableDataChannel: {msg.Segments}");

        byte[]? completed = null;
        lock (_messageLock)
        {
            if (_message.Segments > 0 && _message.Segments - 1 != msg.Segments)
                throw new NetherNetException($"invalid promised segments: expected {_message.Segments - 1}, got {msg.Segments}");

            _message.Segments = msg.Segments;
            _message.Data.AddRange(msg.Data);

            if (_message.Segments == 0)
            {
                completed = _message.Data.ToArray();
                _message.Data.Clear();
            }
        }

        if (completed is not null && !IsClosed)
            _packets.Writer.TryWrite(completed);
    }

    public void Send(byte[] payload)
    {
        _channel.send(payload);
    }

    public void Close()
    {
        if (Interlocked.Exchange(ref _closed, 1) != 0) return;
        lock (_messageLock)
        {
            _message.Data.Clear();
        }
        try
        {
            _channel.close();
        }
        catch (Exception)
        {
            // ignored, mirroring the best-effort closure in the reference implementation.
        }
        _packets.Writer.TryComplete();
    }

    private static Message ParseMessage(byte[] b)
    {
        if (b.Length < 2) throw new NetherNetException("parse: unexpected EOF");
        var msg = new Message { Segments = b[0] };
        msg.Data.AddRange(b.Skip(1));
        return msg;
    }
}