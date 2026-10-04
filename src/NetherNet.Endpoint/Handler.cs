using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;

namespace NetherNet.Endpoint;

public sealed class HandlerConfig
{
    public Action<string>? Logger;
    public Func<CancellationToken, CancellationTokenSource?>? NegotiationContext;
    public Func<CancellationToken, Task<Credentials?>>? Credentials;
    public string NetworkID = "";
    public bool DisablePongData;
}

public sealed class Handler : ISignaling, ITrickleIceDisabler
{
    private const long MaxSdpBodySize = 1 << 20;

    private readonly HandlerConfig _conf;
    private readonly Dictionary<ConnectionKey, Channel<Signal>> _pending = new();
    private readonly object _pendingLock = new();
    private readonly CancellationTokenSource _cts = new();

    private INotifier? _notifier;
    private readonly object _notifierLock = new();

    private string _statusJson = "";
    private readonly object _statusLock = new();

    private HttpListener? _http;
    private Task? _acceptLoop;

    public Handler(HandlerConfig conf)
    {
        conf.Logger ??= _ => { };
        conf.NetworkID = string.IsNullOrEmpty(conf.NetworkID) ? Dialer.RandomUInt64().ToString() : conf.NetworkID;
        _conf = conf;
    }

    public static Handler New() => new(new HandlerConfig());

    public static Handler New(HandlerConfig conf) => new(conf);

    public CancellationToken Context => _cts.Token;

    public Exception? ContextCause { get; private set; }

    public static Handler Serve(string address) => new Handler(new HandlerConfig()).Start(address);

    public static Handler Serve(HandlerConfig conf, string address) => new Handler(conf).Start(address);

    public Handler Start(string address)
    {
        var prefix = BuildPrefix(address);
        var listener = new HttpListener();
        listener.Prefixes.Add(prefix);
        listener.Start();
        _http = listener;
        _acceptLoop = Task.Run(AcceptLoopAsync);
        return this;
    }

    private static string BuildPrefix(string address)
    {
        var host = address;
        var port = "80";
        var idx = address.LastIndexOf(':');
        if (idx >= 0)
        {
            host = address[..idx];
            port = address[(idx + 1)..];
        }
        if (host is "0.0.0.0" or "*" or "+") host = "+";
        return $"http://{host}:{port}/";
    }

    private async Task AcceptLoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            HttpListenerContext ctx;
            try
            {
                ctx = await _http!.GetContextAsync().ConfigureAwait(false);
            }
            catch (Exception)
            {
                return;
            }
            _ = Task.Run(() => HandleContextAsync(ctx));
        }
    }

    private async Task HandleContextAsync(HttpListenerContext ctx)
    {
        try
        {
            var path = ctx.Request.Url?.AbsolutePath ?? "/";
            if (ctx.Request.HttpMethod == "GET" && path == "/v1/join")
            {
                HandlePing(ctx);
                return;
            }
            if (ctx.Request.HttpMethod == "POST" && path.StartsWith("/v1/join/", StringComparison.Ordinal))
            {
                await HandleOfferAsync(ctx, path["/v1/join/".Length..]).ConfigureAwait(false);
                return;
            }
            WriteText(ctx, 404, "Not Found");
        }
        catch (Exception e)
        {
            _conf.Logger?.Invoke($"error handling request: {e.Message}");
            try
            {
                WriteText(ctx, 500, "An error has occured while handling this request");
            }
            catch (Exception)
            {
                // ignored.
            }
        }
    }

    private void HandlePing(HttpListenerContext ctx)
    {
        string status;
        lock (_statusLock) status = _statusJson;
        ctx.Response.KeepAlive = false;
        if (status.Length == 0)
        {
            ctx.Response.StatusCode = 200;
            ctx.Response.Close();
            return;
        }
        var body = Encoding.UTF8.GetBytes(status);
        ctx.Response.StatusCode = 200;
        ctx.Response.ContentType = "application/json";
        ctx.Response.ContentLength64 = body.Length;
        ctx.Response.OutputStream.Write(body);
        ctx.Response.Close();
    }

    private async Task HandleOfferAsync(HttpListenerContext ctx, string networkID)
    {
        ctx.Response.KeepAlive = false;
        if (string.IsNullOrEmpty(networkID) || !ulong.TryParse(networkID, out _))
        {
            WriteText(ctx, 400, "Network ID must be uint64");
            return;
        }

        var body = await ReadBodyAsync(ctx, MaxSdpBodySize).ConfigureAwait(false);
        if (body is null)
        {
            WriteText(ctx, 413, "SDP offer is too large");
            return;
        }
        if (body.Length == 0)
        {
            WriteText(ctx, 400, "Missing SDP offer in request body");
            return;
        }

        using var negCts = CreateNegotiationContext(ctx.Request);
        var negToken = negCts.Token;

        Signal result;
        try
        {
            result = await NegotiateAsync(negToken, networkID, Encoding.UTF8.GetString(body)).ConfigureAwait(false);
        }
        catch (OfferNotAdmittedException)
        {
            WriteText(ctx, 503, "Service unavailable");
            return;
        }
        catch (OperationCanceledException)
        {
            WriteText(ctx, 502, "Timed out waiting for answer");
            return;
        }
        catch (Exception)
        {
            WriteText(ctx, 500, "An error has occured while handling this request");
            return;
        }

        switch (result.Type)
        {
            case SignalType.Answer:
            {
                var data = Encoding.UTF8.GetBytes(result.Data);
                ctx.Response.StatusCode = 200;
                ctx.Response.ContentType = "application/sdp";
                ctx.Response.ContentLength64 = data.Length;
                ctx.Response.OutputStream.Write(data);
                ctx.Response.Close();
                return;
            }
            case SignalType.Error:
            {
                var data = Encoding.UTF8.GetBytes(result.Data);
                ctx.Response.StatusCode = 500;
                ctx.Response.ContentLength64 = data.Length;
                ctx.Response.OutputStream.Write(data);
                ctx.Response.Close();
                return;
            }
            default:
                WriteText(ctx, 500, "An error has occurred while handling this request");
                return;
        }
    }

    private static async Task<byte[]?> ReadBodyAsync(HttpListenerContext ctx, long limit)
    {
        var buffer = new MemoryStream();
        var chunk = new byte[81920];
        int read;
        while ((read = await ctx.Request.InputStream.ReadAsync(chunk).ConfigureAwait(false)) > 0)
        {
            if (buffer.Length + read > limit) return null;
            buffer.Write(chunk, 0, read);
        }
        return buffer.ToArray();
    }

    private CancellationTokenSource CreateNegotiationContext(HttpListenerRequest request)
    {
        var parent = CancellationToken.None;
        var custom = _conf.NegotiationContext?.Invoke(parent);
        if (custom is not null) return custom;
        var cts = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
        cts.CancelAfter(TimeSpan.FromSeconds(15));
        return cts;
    }

    private async Task<Signal> NegotiateAsync(CancellationToken ctx, string networkID, string offer)
    {
        INotifier? notifier;
        lock (_notifierLock) notifier = _notifier;
        if (notifier is null)
            throw new NetherNetException("nethernet/endpoint: no listener registered");

        var signal = new Signal
        {
            Type = SignalType.Offer,
            ConnectionID = Dialer.RandomUInt64(),
            Data = offer,
            NetworkID = networkID,
        };
        var key = new ConnectionKey(networkID, signal.ConnectionID);
        var channel = Channel.CreateBounded<Signal>(1);

        lock (_pendingLock) _pending[key] = channel;

        try
        {
            if (!notifier.NotifySignal(signal))
                throw new OfferNotAdmittedException();

            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ctx, _cts.Token);
            try
            {
                return await channel.Reader.ReadAsync(linked.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                notifier.NotifySignal(new Signal
                {
                    Type = SignalType.Error,
                    ConnectionID = signal.ConnectionID,
                    Data = ErrorCode.NegotiationTimeoutWaitingForResponse.ToString(),
                    NetworkID = signal.NetworkID,
                });
                throw;
            }
        }
        finally
        {
            lock (_pendingLock) _pending.Remove(key);
        }
    }

    public Task SignalAsync(CancellationToken ctx, Signal signal)
    {
        if (signal.Type == SignalType.Candidate)
            throw new NetherNetException("disable trickle ICE in ListenConfig.DisableTrickleICE");

        var key = new ConnectionKey(signal.NetworkID, signal.ConnectionID);
        Channel<Signal>? channel;
        lock (_pendingLock) channel = _pending.TryGetValue(key, out var c) ? c : null;
        if (channel is null)
            throw new NetherNetException($"unexpected connection ID: {key}");

        if (ctx.IsCancellationRequested) throw new NetherNetException("nethernet: operation canceled");
        if (!channel.Writer.TryWrite(signal))
            throw new NetherNetException("channel buffer is full");
        return Task.CompletedTask;
    }

    public Action Notify(INotifier n)
    {
        lock (_notifierLock)
        {
            if (_notifier is not null)
                throw new NetherNetException("nethernet/endpoint: Handler.Notify: listener already registered");
            _notifier = n;
            return () =>
            {
                lock (_notifierLock)
                {
                    if (ReferenceEquals(_notifier, n)) _notifier = null;
                }
            };
        }
    }

    public Task<Credentials?> CredentialsAsync(CancellationToken ctx)
        => _conf.Credentials is null ? Task.FromResult<Credentials?>(new Credentials()) : _conf.Credentials(ctx);

    public string NetworkID() => _conf.NetworkID;

    public bool DisableTrickleICE() => true;

    public void PongData(byte[] data)
    {
        if (_conf.DisablePongData) return;
        try
        {
            Status(NetherNet.Endpoint.Status.RakNetPongData(data));
        }
        catch (Exception e)
        {
            _conf.Logger?.Invoke($"error parsing RakNet pong data: {e.Message}");
        }
    }

    public void Status(Status status)
    {
        var json = JsonSerializer.Serialize(status);
        lock (_statusLock) _statusJson = json;
    }

    public void Close()
    {
        if (_cts.IsCancellationRequested) return;
        ContextCause = new NetherNetException("nethernet: handler is closed");
        try
        {
            _cts.Cancel();
        }
        catch (Exception)
        {
            // ignored.
        }
        try
        {
            _http?.Close();
        }
        catch (Exception)
        {
            // ignored.
        }
    }

    private static void WriteText(HttpListenerContext ctx, int statusCode, string text)
    {
        var body = Encoding.UTF8.GetBytes(text);
        ctx.Response.StatusCode = statusCode;
        ctx.Response.ContentType = "text/plain";
        ctx.Response.ContentLength64 = body.Length;
        try
        {
            ctx.Response.OutputStream.Write(body);
        }
        catch (Exception)
        {
            // ignored.
        }
        ctx.Response.Close();
    }

    private readonly record struct ConnectionKey(string NetworkID, ulong ConnectionID);

    private sealed class OfferNotAdmittedException : Exception
    {
    }
}