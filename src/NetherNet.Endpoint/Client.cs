using System.Text;

namespace NetherNet.Endpoint;

public sealed class ClientConfig
{
    public HttpClient? HttpClient;
    public Func<CancellationToken, Task<Credentials?>>? Credentials;
    public Action<string>? Logger;
    public string NetworkID = "";
}

public sealed class Client : ISignaling, ITrickleIceDisabler
{
    private const long MaxSdpBodySize = 1 << 20;

    private readonly ClientConfig _conf;
    private readonly Dictionary<uint, INotifier> _notifiers = new();
    private readonly object _notifiersLock = new();
    private uint _notifyCount;

    public Client(ClientConfig conf)
    {
        conf.HttpClient ??= new HttpClient();
        conf.NetworkID = string.IsNullOrEmpty(conf.NetworkID) ? Dialer.RandomUInt64().ToString() : conf.NetworkID;
        _conf = conf;
    }

    public static Client New() => new(new ClientConfig());

    public static Client New(ClientConfig conf) => new(conf);

    public async Task<byte[]> PingContextAsync(CancellationToken ctx, string address)
    {
        var status = await StatusAsync(ctx, address).ConfigureAwait(false);
        return status.RakNet();
    }

    public async Task<Status> StatusAsync(CancellationToken ctx, string address)
    {
        var u = ParseUrl(address);
        var requestUrl = $"{u.Scheme}://{u.Authority}/v1/join";

        using var request = new HttpRequestMessage(HttpMethod.Get, requestUrl);
        request.Headers.TryAddWithoutValidation("User-Agent", "libhttpclient/1.0.0.0");

        using var response = await _conf.HttpClient!.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ctx).ConfigureAwait(false);
        if (response.StatusCode != System.Net.HttpStatusCode.OK)
            throw new NetherNetException($"{request.Method} {requestUrl}: {response.StatusCode}");

        var body = await response.Content.ReadAsByteArrayAsync(ctx).ConfigureAwait(false);
        return System.Text.Json.JsonSerializer.Deserialize<Status>(body) ?? throw new NetherNetException("decode response body");
    }

    private static Uri ParseUrl(string s)
    {
        if (!Uri.TryCreate(s, UriKind.Absolute, out var u))
            throw new NetherNetException($"parse network ID as URL: {s}");
        if ((u.Scheme != "https" && u.Scheme != "http") || u.AbsolutePath != "/" || u.IsDefaultPort)
            throw new NetherNetException($"network ID must be a HTTP/HTTPS URL with port: {s}");
        return u;
    }

    public async Task SignalAsync(CancellationToken ctx, Signal signal)
    {
        var u = ParseUrl(signal.NetworkID);

        switch (signal.Type)
        {
            case SignalType.Offer:
            {
                var requestUrl = $"{u.Scheme}://{u.Authority}/v1/join/{_conf.NetworkID}";
                using var request = new HttpRequestMessage(HttpMethod.Post, requestUrl)
                {
                    Content = new StringContent(signal.Data, Encoding.UTF8, "application/sdp"),
                };
                request.Headers.TryAddWithoutValidation("User-Agent", "libhttpclient/1.0.0.0");

                using var response = await _conf.HttpClient!.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ctx).ConfigureAwait(false);
                if (response.StatusCode != System.Net.HttpStatusCode.OK)
                    throw new NetherNetException($"{request.Method} {requestUrl}: {response.StatusCode}");

                var body = await response.Content.ReadAsByteArrayAsync(ctx).ConfigureAwait(false);
                if (body.Length > MaxSdpBodySize)
                    throw new NetherNetException($"SDP answer exceeds {MaxSdpBodySize} bytes");
                if (body.Length == 0)
                    throw new NetherNetException("missing SDP answer in response body");

                var text = Encoding.UTF8.GetString(body);
                if (uint.TryParse(text, out var errorCode))
                    throw new NetherNetException($"negotiation failed with error code: {errorCode}");

                NotifySignal(new Signal
                {
                    Type = SignalType.Answer,
                    ConnectionID = signal.ConnectionID,
                    Data = text,
                    NetworkID = signal.NetworkID,
                });
                return;
            }
            case SignalType.Error:
                return;
            case SignalType.Candidate:
                throw new NetherNetException("nethernet/endpoint: trickle ICE is not supported");
            default:
                throw new NetherNetException($"nethernet/endpoint: unknown signal type: {signal.Type}");
        }
    }

    public bool DisableTrickleICE() => true;

    public Action Notify(INotifier n)
    {
        lock (_notifiersLock)
        {
            var i = _notifyCount;
            _notifyCount++;
            _notifiers[i] = n;
            return () =>
            {
                lock (_notifiersLock)
                {
                    _notifiers.Remove(i);
                }
            };
        }
    }

    public CancellationToken Context => CancellationToken.None;

    public Exception? ContextCause => null;

    public Task<Credentials?> CredentialsAsync(CancellationToken ctx)
        => _conf.Credentials is null ? Task.FromResult<Credentials?>(new Credentials()) : _conf.Credentials(ctx);

    public string NetworkID() => _conf.NetworkID;

    public void PongData(byte[] b) => throw new NotSupportedException("nethernet/endpoint: Client.PongData: unsupported");

    private void NotifySignal(Signal signal)
    {
        List<INotifier> notifiers;
        lock (_notifiersLock)
        {
            notifiers = new List<INotifier>(_notifiers.Values);
        }
        foreach (var n in notifiers) n.NotifySignal(signal);
    }
}