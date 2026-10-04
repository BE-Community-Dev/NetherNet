using System.Net;
using System.Net.Sockets;
using System.Text;

namespace NetherNet.Discovery;

public sealed class ListenConfig
{
    public ulong NetworkID;
    public IPEndPoint? BroadcastAddress;
    public Action<string>? Log;
}

public sealed class Listener : NetherNet.ISignaling
{
    public const int DefaultPort = 7551;
    private const int MaxUdpPacketSize = 65535;

    private readonly Socket _socket;
    private readonly ListenConfig _conf;
    private readonly CancellationTokenSource _closedCts = new();

    private byte[]? _pongData;

    private readonly Dictionary<ulong, AddressInfo> _addresses = new();
    private readonly object _addressesLock = new();

    private readonly Dictionary<uint, NetherNet.INotifier> _notifiers = new();
    private readonly object _notifiersLock = new();
    private uint _notifyCount;

    private readonly Dictionary<ulong, byte[]> _responses = new();
    private readonly object _responsesLock = new();

    private int _closed;

    private Listener(Socket socket, ListenConfig conf)
    {
        _socket = socket;
        _conf = conf;
    }

    public Listener Listen(string addr)
    {
        if (_conf.NetworkID == 0) _conf.NetworkID = NetherNet.Dialer.RandomUInt64();
        if (string.IsNullOrEmpty(addr)) addr = ":0";

        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp)
        {
            EnableBroadcast = true,
        };
        socket.Bind(ParseAddr(addr));

        if (_conf.BroadcastAddress is null && socket.LocalEndPoint is IPEndPoint local && local.Port != DefaultPort)
            _conf.BroadcastAddress = new IPEndPoint(IPAddress.Broadcast, DefaultPort);

        var listener = new Listener(socket, _conf);
        _ = Task.Run(listener.ListenLoop);
        _ = Task.Run(listener.BackgroundAsync);
        return listener;
    }

    private static IPEndPoint ParseAddr(string addr)
    {
        if (addr.StartsWith(':')) return new IPEndPoint(IPAddress.Any, int.Parse(addr[1..]));
        return IPEndPoint.Parse(addr);
    }

    public CancellationToken Context => _closedCts.Token;

    public Exception? ContextCause { get; private set; }

    public string NetworkID() => _conf.NetworkID.ToString();

    public Task<Credentials?> CredentialsAsync(CancellationToken ctx)
    {
        if (Volatile.Read(ref _closed) != 0) throw new NetherNetException("nethernet: listener is closed");
        return Task.FromResult<Credentials?>(null);
    }

    public Action Notify(NetherNet.INotifier n)
    {
        lock (_notifiersLock)
        {
            var i = _notifyCount;
            _notifiers[i] = n;
            _notifyCount++;
            return () =>
            {
                lock (_notifiersLock)
                {
                    _notifiers.Remove(i);
                }
            };
        }
    }

    public async Task SignalAsync(CancellationToken ctx, NetherNet.Signal signal)
    {
        if (ctx.IsCancellationRequested) throw new NetherNetException("nethernet: operation canceled");
        if (Volatile.Read(ref _closed) != 0) throw new NetherNetException("nethernet: listener is closed");

        if (!ulong.TryParse(signal.NetworkID, out var networkID))
            throw new NetherNetException("parse network ID as uint64: invalid syntax");

        AddressInfo? address;
        lock (_addressesLock)
        {
            address = _addresses.TryGetValue(networkID, out var a) ? a : null;
        }
        if (address is null)
            throw new NetherNetException($"no address found for network ID: {networkID}");

        var packet = new MessagePacket { RecipientID = networkID, Data = signal.ToString() };
        Write(packet, address.EndPoint);
        await Task.CompletedTask.ConfigureAwait(false);
    }

    public Dictionary<ulong, byte[]> Responses()
    {
        lock (_responsesLock)
        {
            return new Dictionary<ulong, byte[]>(_responses);
        }
    }

    public void ServerData(ServerData d) => _pongData = d.MarshalBinary();

    public void PongData(byte[] b)
    {
        var parts = Encoding.UTF8.GetString(b).Split(';');
        if (parts.Length < 9)
        {
            _conf.Log?.Invoke($"unexpected pong data format: {Encoding.UTF8.GetString(b)}");
            return;
        }
        _ = int.TryParse(parts[4], out var players);
        _ = int.TryParse(parts[5], out var maxPlayers);
        var gameType = ParsePongGameType(parts[8]);

        ServerData(new ServerData
        {
            ServerName = parts[1],
            LevelName = parts[7],
            GameType = gameType,
            PlayerCount = players,
            MaxPlayerCount = maxPlayers,
            EditorWorld = false,
            Hardcore = false,
            AcceptsOnlineAuth = true,
            AcceptsSelfSignedAuth = true,
            ConnectionType = 4,
        });
    }

    private static int ParsePongGameType(string v) => v.Trim().ToLowerInvariant() switch
    {
        "survival" => GameType.Survival,
        "creative" => GameType.Creative,
        "adventure" => GameType.Adventure,
        _ => 0,
    };

    private void ListenLoop()
    {
        var buffer = new byte[MaxUdpPacketSize];
        while (Volatile.Read(ref _closed) == 0)
        {
            int n;
            EndPoint from = new IPEndPoint(IPAddress.Any, 0);
            try
            {
                n = _socket.ReceiveFrom(buffer, ref from);
            }
            catch (Exception)
            {
                Close();
                return;
            }

            try
            {
                HandlePacket(buffer.AsSpan(0, n).ToArray(), from);
            }
            catch (Exception e)
            {
                _conf.Log?.Invoke($"error handling packet from {from}: {e.Message}");
            }
        }
    }

    private void Write(Packet pk, EndPoint addr)
    {
        var b = PacketCodec.Marshal(pk, _conf.NetworkID);
        _socket.SendTo(b, SocketFlags.None, addr);
    }

    private void HandlePacket(byte[] data, EndPoint addr)
    {
        Packet pk;
        ulong senderID;
        try
        {
            (pk, senderID) = PacketCodec.Unmarshal(data);
        }
        catch (Exception e)
        {
            throw new NetherNetException($"decode: {e.Message}", e);
        }

        if (senderID == _conf.NetworkID) return;

        lock (_addressesLock)
        {
            if (!_addresses.TryGetValue(senderID, out var a)) a = new AddressInfo { NetworkID = senderID };
            a.EndPoint = addr;
            a.Timestamp = DateTime.UtcNow;
            _addresses[senderID] = a;
        }

        switch (pk)
        {
            case RequestPacket:
                HandleRequest(addr);
                break;
            case ResponsePacket response:
                lock (_responsesLock) _responses[senderID] = response.ApplicationData;
                break;
            case MessagePacket message:
                HandleMessage(message, senderID);
                break;
            default:
                throw new NetherNetException($"unknown packet: {pk.GetType().Name}");
        }
    }

    private void HandleRequest(EndPoint addr)
    {
        var data = _pongData;
        if (data is null) throw new NetherNetException("application data not set yet");
        Write(new ResponsePacket { ApplicationData = data }, addr);
    }

    private void HandleMessage(MessagePacket pk, ulong senderID)
    {
        if (pk.RecipientID != _conf.NetworkID) return;
        if (pk.Data is "Ping" or "") return;

        NetherNet.Signal signal;
        try
        {
            signal = NetherNet.Signal.Parse(pk.Data);
        }
        catch (Exception e)
        {
            throw new NetherNetException($"decode signal: {e.Message}", e);
        }
        signal.NetworkID = senderID.ToString();

        List<NetherNet.INotifier> notifiers;
        lock (_notifiersLock)
        {
            notifiers = new List<NetherNet.INotifier>(_notifiers.Values);
        }
        foreach (var n in notifiers) n.NotifySignal(signal);
    }

    private async Task BackgroundAsync()
    {
        while (Volatile.Read(ref _closed) == 0)
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(2), _closedCts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            DeleteInactiveAddresses();

            if (_conf.BroadcastAddress is not null)
            {
                try
                {
                    Write(new RequestPacket(), _conf.BroadcastAddress);
                }
                catch (Exception)
                {
                    // socket closed or broadcast failed; ignore.
                }
            }
        }
    }

    private void DeleteInactiveAddresses()
    {
        lock (_addressesLock)
        {
            var expired = _addresses.Where(kv => DateTime.UtcNow - kv.Value.Timestamp > TimeSpan.FromSeconds(15)).Select(kv => kv.Key).ToList();
            foreach (var key in expired) _addresses.Remove(key);
        }
    }

    public void Close()
    {
        if (Interlocked.Exchange(ref _closed, 1) != 0) return;
        ContextCause = new NetherNetException("nethernet: listener is closed");
        try
        {
            _closedCts.Cancel();
        }
        catch (Exception)
        {
            // ignored.
        }
        try
        {
            _socket.Close();
        }
        catch (Exception)
        {
            // ignored.
        }
        lock (_notifiersLock)
        {
            _notifiers.Clear();
        }
    }

    private sealed class AddressInfo
    {
        public ulong NetworkID;
        public DateTime Timestamp;
        public EndPoint EndPoint = new IPEndPoint(IPAddress.Any, 0);
    }
}