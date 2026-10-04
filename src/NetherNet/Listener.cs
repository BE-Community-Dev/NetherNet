using System.Security.Cryptography;
using System.Threading.Channels;
using SIPSorcery.Net;

namespace NetherNet;

public sealed class ListenConfig
{
    public Action<string>? Log;
    public Func<CancellationToken, Conn, CancellationTokenSource?>? ConnContext;
    public Func<CancellationToken, CancellationTokenSource?>? NegotiationContext;
    public Func<CancellationToken, Task<Identity>>? IssueServerIdentity;
    public Func<CancellationToken, string, Task<ECDsa?>>? VerifyClientToken;
    public bool AllowAnonymous;
    public IceGatherPolicy IceGatherPolicy = IceGatherPolicy.All;
    public bool DisableTrickleICE = true;
}

public sealed class Listener : INotifier
{
    private const int MaxListenerNegotiations = 64;
    private const int MaxPendingSignalsPerNegotiation = 32;

    private readonly ListenConfig _conf;
    private readonly ISignaling _signaling;
    private readonly string _networkID;
    private readonly ulong _id;

    private readonly Channel<Conn> _incoming = Channel.CreateUnbounded<Conn>();
    private readonly Dictionary<NegotiationKey, ListenerNegotiator> _negotiations = new();
    private readonly object _negotiationsLock = new();
    private readonly SemaphoreSlim _sem = new(MaxListenerNegotiations, MaxListenerNegotiations);

    private readonly CancellationTokenSource _closedCts = new();
    private Action? _stop;
    private int _closed;

    internal Listener(ListenConfig conf, ISignaling signaling, string networkID)
    {
        _conf = conf;
        _signaling = signaling;
        _networkID = networkID;
        _id = ulong.TryParse(networkID, out var parsed) ? parsed : Dialer.RandomUInt64();
    }

    internal ListenConfig Conf => _conf;

    internal ISignaling Signaling => _signaling;

    internal string NetworkIdInternal => _networkID;

    public CancellationToken Context => _closedCts.Token;

    public static Task<Listener> ListenAsync(ISignaling signaling) => new ListenConfig().ListenAsync(signaling);

    public static Task<Listener> ListenAsync(ListenConfig conf, ISignaling signaling) => conf.ListenAsync(signaling);

    public string NetworkID() => _networkID;

    public long ID() => (long)_id;

    public void PongData(byte[] b) => _signaling.PongData(b);

    public Addr Addr() => new() { NetworkID = _networkID };

    internal void Start()
    {
        _stop = _signaling.Notify(this);
        _ = Task.Run(MonitorSignalingAsync);
    }

    private async Task MonitorSignalingAsync()
    {
        try
        {
            await Task.Delay(Timeout.Infinite, _signaling.Context).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }
        Close();
    }

    public async Task<Conn> AcceptAsync(CancellationToken ctx = default)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ctx, _closedCts.Token);
        try
        {
            return await _incoming.Reader.ReadAsync(linked.Token).ConfigureAwait(false);
        }
        catch (ChannelClosedException)
        {
            throw new NetherNetException("nethernet: listener is closed");
        }
        catch (OperationCanceledException)
        {
            throw new NetherNetException("nethernet: listener is closed");
        }
    }

    public bool NotifySignal(Signal signal)
    {
        try
        {
            signal.Validate();
        }
        catch (Exception)
        {
            return false;
        }

        lock (_negotiationsLock)
        {
            if (_closed != 0 || _signaling.Context.IsCancellationRequested) return false;

            var key = new NegotiationKey(signal.NetworkID, signal.ConnectionID);
            if (!_negotiations.TryGetValue(key, out var negotiator))
            {
                if (signal.Type != SignalType.Offer) return false;
                if (!_sem.Wait(0)) return false;

                negotiator = new ListenerNegotiator(this, key);
                _negotiations[key] = negotiator;
                _ = Task.Run(() => negotiator.NegotiateAsync(signal));
                return true;
            }

            return negotiator.HandleSignal(signal);
        }
    }

    internal void ReleaseSemaphore() => _sem.Release();

    internal void Unregister(ListenerNegotiator negotiator)
    {
        lock (_negotiationsLock)
        {
            if (_negotiations.TryGetValue(negotiator.Key, out var existing) && ReferenceEquals(existing, negotiator))
                _negotiations.Remove(negotiator.Key);
        }
    }

    internal async Task IssueIncomingAsync(Conn conn) => await _incoming.Writer.WriteAsync(conn).ConfigureAwait(false);

    public void Close()
    {
        if (Interlocked.Exchange(ref _closed, 1) != 0) return;
        List<ListenerNegotiator> owners;
        lock (_negotiationsLock)
        {
            owners = new List<ListenerNegotiator>(_negotiations.Values);
        }
        try
        {
            _closedCts.Cancel();
        }
        catch (Exception)
        {
            // ignored.
        }
        foreach (var n in owners) n.Close();
        _stop?.Invoke();
        _incoming.Writer.TryComplete();
    }
}

internal readonly record struct NegotiationKey(string NetworkID, ulong ConnectionID);

internal sealed class ListenerNegotiator : INegotiator
{
    private readonly Listener _listener;
    private readonly CancellationTokenSource _closedCts = new();
    private readonly object _lock = new();
    private readonly List<Signal> _deferred = new();

    private Conn? _conn;
    private bool _finished;
    private int _closed;
    private int _remoteCanceled;

    public ListenerNegotiator(Listener listener, NegotiationKey key)
    {
        _listener = listener;
        Key = key;
    }

    public NegotiationKey Key { get; }

    public CancellationToken Context => _closedCts.Token;

    public bool HandleSignal(Signal signal)
    {
        if (IsClosed) return false;

        switch (signal.Type)
        {
            case SignalType.Offer:
                return false;
            case SignalType.Error:
                Interlocked.Exchange(ref _remoteCanceled, 1);
                Conn? conn;
                lock (_lock) conn = _conn;
                if (conn is not null)
                {
                    try
                    {
                        conn.HandleSignal(signal);
                    }
                    catch (Exception)
                    {
                        return false;
                    }
                }
                else
                {
                    Close();
                }
                return true;
            case SignalType.Candidate:
                Conn? c;
                lock (_lock)
                {
                    if (IsClosed) return false;
                    c = _conn;
                    if (c is null)
                    {
                        if (_deferred.Count >= 32) return false;
                        _deferred.Add(signal);
                        return true;
                    }
                }
                if (c.Context.IsCancellationRequested) return false;
                try
                {
                    c.HandleSignal(signal);
                    return true;
                }
                catch (Exception)
                {
                    return false;
                }
            default:
                return false;
        }
    }

    public async Task NegotiateAsync(Signal offer)
    {
        try
        {
            try
            {
                await HandleOfferAsync(offer).ConfigureAwait(false);
            }
            catch (Exception e)
            {
                Close();
                _listener.Conf.Log?.Invoke($"error handling offer: {e}");
                ReportError(e);
                return;
            }
        }
        finally
        {
            Finish();
        }
    }

    private void Finish()
    {
        bool closed;
        lock (_lock)
        {
            _finished = true;
            closed = _closed != 0;
        }
        if (closed) _listener.Unregister(this);
        _listener.ReleaseSemaphore();
    }

    private void ReportError(Exception err)
    {
        if (Volatile.Read(ref _remoteCanceled) != 0) return;
        if (err is SignalException se) SignalError(se.Code);
    }

    private void SignalError(int code)
    {
        _ = Task.Run(async () =>
        {
            try
            {
                using var cts = new CancellationTokenSource(Dialer.SignalErrorTimeout);
                await _listener.Signaling.SignalAsync(cts.Token, new Signal
                {
                    Type = SignalType.Error,
                    ConnectionID = Key.ConnectionID,
                    NetworkID = Key.NetworkID,
                    Data = code.ToString(),
                }).ConfigureAwait(false);
            }
            catch (Exception)
            {
                // best-effort.
            }
        });
    }

    private async Task HandleOfferAsync(Signal signal)
    {
        SdpSession offerSdp;
        Description remoteDesc;
        try
        {
            offerSdp = SdpSession.Parse(signal.Data);
            remoteDesc = DescriptionParser.ParseDescription(offerSdp);
        }
        catch (Exception e)
        {
            throw SignalErrors.Wrap(new NetherNetException("parse offer", e), ErrorCode.FailedToSetRemoteDescription);
        }

        using var negCts = CreateContext(_listener.Conf.NegotiationContext, Context, TimeSpan.FromSeconds(15));
        var negToken = negCts.Token;

        Credentials? credentials;
        try
        {
            credentials = await _listener.Signaling.CredentialsAsync(negToken).ConfigureAwait(false);
        }
        catch (Exception e)
        {
            throw SignalErrors.Wrap(new NetherNetException("obtain credentials", e), ErrorCode.SignalingTurnAuthFailed);
        }

        var config = Peer.BuildConfiguration(credentials, _listener.Conf.IceGatherPolicy);
        var peer = Peer.CreatePeer(config);
        var conn = new Conn(peer, signal.ConnectionID, signal.NetworkID, _listener.NetworkIdInternal, this);
        var established = false;

        try
        {
            var opened = 0;
            var channelsReady = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            peer.ondatachannel += channel =>
            {
                for (var i = 0; i < MessageReliabilityExtensions.Capacity; i++)
                {
                    var r = (MessageReliability)i;
                    if (!r.Valid(channel)) continue;
                    conn.AttachDataChannel(channel, r);
                    void OnOpen()
                    {
                        if (Interlocked.Increment(ref opened) == MessageReliabilityExtensions.Capacity)
                            channelsReady.TrySetResult(true);
                    }
                    channel.onopen += OnOpen;
                    if (channel.readyState == RTCDataChannelState.open) OnOpen();
                    return;
                }
                conn.Close(new NetherNetException($"nethernet: invalid data channel opened: \"{channel.label}\""));
            };

            var result = peer.setRemoteDescription(new RTCSessionDescriptionInit
            {
                type = RTCSdpType.offer,
                sdp = Peer.SanitizeForPeer(signal.Data),
            });
            if (result != SetDescriptionResultEnum.OK)
                throw SignalErrors.Wrap(new NetherNetException($"set remote description failed: {result}"), ErrorCode.FailedToSetRemoteDescription);

            for (var i = 0; i < remoteDesc.RawCandidates.Count; i++)
                conn.AddRemoteCandidate(remoteDesc.RawCandidates[i]);

            if (remoteDesc.Identity is not null)
            {
                ECDsa? publicKey;
                try
                {
                    publicKey = _listener.Conf.VerifyClientToken is null
                        ? Jwt.ClaimPublicKey(remoteDesc.Identity.Assertion.Token, false)
                        : await _listener.Conf.VerifyClientToken(negToken, remoteDesc.Identity.Assertion.Token).ConfigureAwait(false)
                            ?? Jwt.ClaimPublicKey(remoteDesc.Identity.Assertion.Token, false);
                }
                catch (Exception e)
                {
                    throw SignalErrors.Wrap(new NetherNetException("verify client token", e), ErrorCode.IdentityNotAllowed);
                }
                try
                {
                    remoteDesc.Identity.Verify(remoteDesc, publicKey);
                }
                catch (Exception e)
                {
                    throw SignalErrors.Wrap(new NetherNetException("verify identity assertion", e), ErrorCode.IdentityNotAllowed);
                }
                conn.PublicKey = publicKey;
            }
            else if (!_listener.Conf.AllowAnonymous)
            {
                throw SignalErrors.Wrap(new NetherNetException("nethernet: anonymous identity not allowed"), ErrorCode.IdentityNotAllowed);
            }

            Identity identity;
            try
            {
                identity = await _listener.Conf.IssueServerIdentity!(negToken).ConfigureAwait(false);
            }
            catch (Exception e)
            {
                throw SignalErrors.Wrap(new NetherNetException("issue server identity", e), ErrorCode.FailedToCreateIdentityAssertion);
            }

            var answerInit = peer.createAnswer(null!);
            await peer.setLocalDescription(answerInit).ConfigureAwait(false);
            var candidates = await Peer.GatherCandidatesAsync(peer, TimeSpan.FromSeconds(5), negToken).ConfigureAwait(false);

            var answerSdp = SdpSession.Parse(answerInit.sdp);
            Peer.InjectCandidates(answerSdp, candidates);
            try
            {
                Peer.ApplyIdentity(answerSdp, identity);
            }
            catch (Exception e)
            {
                throw SignalErrors.Wrap(new NetherNetException("generate identity assertion", e), ErrorCode.FailedToCreateIdentityAssertion);
            }

            try
            {
                await _listener.Signaling.SignalAsync(negToken, new Signal
                {
                    Type = SignalType.Answer,
                    ConnectionID = signal.ConnectionID,
                    Data = answerSdp.ToString(),
                    NetworkID = signal.NetworkID,
                }).ConfigureAwait(false);
            }
            catch (Exception e)
            {
                throw SignalErrors.Wrap(new NetherNetException("signal answer", e), ErrorCode.SignalingFailedToSend);
            }

            List<Signal> deferred;
            lock (_lock)
            {
                if (_closed != 0 || Volatile.Read(ref _remoteCanceled) != 0)
                    throw new NetherNetException("nethernet: negotiation canceled");
                _conn = conn;
                deferred = new List<Signal>(_deferred);
                _deferred.Clear();
            }
            foreach (var s in deferred) HandleSignal(s);

            if (peer.sctp is not null)
                conn.SetMaxSegmentPayload(peer.sctp.maxMessageSize - 1);

            await WaitChannelsReadyAsync(conn, channelsReady.Task, negToken).ConfigureAwait(false);
            await _listener.IssueIncomingAsync(conn).ConfigureAwait(false);
            established = true;
        }
        finally
        {
            if (!established)
            {
                conn.Close();
            }
        }
    }

    private async Task WaitChannelsReadyAsync(Conn conn, Task ready, CancellationToken negToken)
    {
        var closedTask = Task.Delay(Timeout.Infinite, Context);
        var connClosedTask = Task.Delay(Timeout.Infinite, conn.Context);
        var negTask = Task.Delay(Timeout.Infinite, negToken);
        var finished = await Task.WhenAny(ready, closedTask, connClosedTask, negTask).ConfigureAwait(false);
        if (finished == ready) return;
        if (conn.Context.IsCancellationRequested)
            throw new NetherNetException("nethernet: connection is closed", conn.ContextCause);
        if (negToken.IsCancellationRequested)
            throw new NetherNetException("nethernet: negotiation deadline exceeded");
        throw new NetherNetException("nethernet: listener is closed");
    }

    private static CancellationTokenSource CreateContext(Func<CancellationToken, CancellationTokenSource?>? factory, CancellationToken parent, TimeSpan timeout)
    {
        var custom = factory?.Invoke(parent);
        if (custom is not null) return custom;
        var cts = CancellationTokenSource.CreateLinkedTokenSource(parent);
        cts.CancelAfter(timeout);
        return cts;
    }

    public void HandleClose(Conn conn) => Close();

    private bool IsClosed => Volatile.Read(ref _closed) != 0;

    public void Close()
    {
        if (Interlocked.Exchange(ref _closed, 1) != 0) return;
        try
        {
            _closedCts.Cancel();
        }
        catch (Exception)
        {
            // ignored.
        }
        bool finished;
        lock (_lock)
        {
            _deferred.Clear();
            finished = _finished;
        }
        if (finished) _listener.Unregister(this);
    }
}

public static class ListenConfigExtensions
{
    public static async Task<Listener> ListenAsync(this ListenConfig conf, ISignaling signaling)
    {
        conf.IssueServerIdentity ??= _ =>
        {
            var key = ECDsa.Create(ECCurve.NamedCurves.nistP384);
            return Task.FromResult(Identity.GenerateServerIdentity(key, "self"));
        };
        conf.VerifyClientToken ??= (_, token) => Task.FromResult<ECDsa?>(Jwt.ClaimPublicKey(token, false));

        var listener = new Listener(conf, signaling, signaling.NetworkID());
        listener.Start();
        await Task.CompletedTask.ConfigureAwait(false);
        return listener;
    }
}