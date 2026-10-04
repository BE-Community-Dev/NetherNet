using System.Security.Cryptography;
using System.Threading.Channels;
using SIPSorcery.Net;

namespace NetherNet;

public sealed class Dialer
{
    public ulong ConnectionID;
    public Action<string>? Log;
    public Identity? Identity;
    public Func<CancellationToken, string, string, Task<ECDsa?>>? VerifyServerToken;
    public bool AllowIdentitylessServer;
    public IceGatherPolicy IceGatherPolicy = IceGatherPolicy.All;
    public Func<CancellationToken, Task<Credentials?>>? Credentials;
    public bool DisableTrickleICE;

    public static TimeSpan SignalErrorTimeout => TimeSpan.FromSeconds(2);

    public static Task<Conn> Dial(string networkID, ISignaling signaling)
        => new Dialer().DialAsync(networkID, signaling);

    public static Task<Conn> DialContext(CancellationToken ctx, string networkID, ISignaling signaling)
        => new Dialer().DialContextAsync(ctx, networkID, signaling);

    public async Task<Conn> DialAsync(string networkID, ISignaling signaling)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        return await DialContextAsync(cts.Token, networkID, signaling).ConfigureAwait(false);
    }

    public async Task<Conn> DialContextAsync(CancellationToken ctx, string networkID, ISignaling signaling)
    {
        if (ConnectionID == 0) ConnectionID = RandomUInt64();
        VerifyServerToken ??= (_, token, _) => Task.FromResult<ECDsa?>(Jwt.ClaimPublicKey(token, true));

        var credentialsFunc = Credentials ?? signaling.CredentialsAsync;
        var credentials = await credentialsFunc(ctx).ConfigureAwait(false);

        var notifier = new DialerNotifier(this, networkID);
        var stop = signaling.Notify(notifier);
        var stopped = 0;
        void Stop()
        {
            if (Interlocked.Exchange(ref stopped, 1) != 0) return;
            notifier.Complete();
            stop();
        }

        var config = Peer.BuildConfiguration(credentials, IceGatherPolicy);
        var peer = Peer.CreatePeer(config);
        var conn = new Conn(peer, ConnectionID, networkID, signaling.NetworkID(), new DialerNegotiator(Stop));

        var opened = 0;
        var channelsOpened = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        for (var i = 0; i < MessageReliabilityExtensions.Capacity; i++)
        {
            var r = (MessageReliability)i;
            var dc = await peer.createDataChannel(r.Label(), r.Parameters()).ConfigureAwait(false);
            conn.AttachDataChannel(dc, r);
            void OnOpen()
            {
                if (Interlocked.Increment(ref opened) == MessageReliabilityExtensions.Capacity)
                    channelsOpened.TrySetResult(true);
            }
            dc.onopen += OnOpen;
            if (dc.readyState == RTCDataChannelState.open) OnOpen();
        }

        try
        {
            var offerInit = peer.createOffer(null!);
            await peer.setLocalDescription(offerInit).ConfigureAwait(false);
            var candidates = await Peer.GatherCandidatesAsync(peer, TimeSpan.FromSeconds(5), ctx).ConfigureAwait(false);

            var sdp = SdpSession.Parse(offerInit.sdp);
            Peer.InjectCandidates(sdp, candidates);
            conn.SetLocalCandidates(candidates.Select(IceCandidateParser.ParseRemoteCandidate).ToList());
            if (Identity is not null) Peer.ApplyIdentity(sdp, Identity);

            await signaling.SignalAsync(ctx, new Signal
            {
                Type = SignalType.Offer,
                Data = sdp.ToString(),
                ConnectionID = ConnectionID,
                NetworkID = networkID,
            }).ConfigureAwait(false);

            while (true)
            {
                if (conn.Context.IsCancellationRequested)
                    throw new NetherNetException("nethernet: connection is closed", conn.ContextCause);
                if (ctx.IsCancellationRequested)
                {
                    SignalError(signaling, networkID, ErrorCode.NegotiationTimeoutWaitingForResponse);
                    throw new NetherNetException("nethernet: negotiation deadline exceeded");
                }
                if (signaling.Context.IsCancellationRequested)
                    throw new NetherNetException("nethernet: signaling is closed", signaling.ContextCause);

                var signal = await ReadSignalAsync(notifier, ctx, conn, signaling).ConfigureAwait(false);
                if (signal is null)
                    throw new NetherNetException("nethernet: signaling is closed");

                if (signal.Type != SignalType.Answer)
                {
                    conn.HandleSignal(signal);
                    continue;
                }

                SdpSession answerSdp;
                Description desc;
                try
                {
                    answerSdp = SdpSession.Parse(signal.Data);
                    desc = DescriptionParser.ParseDescription(answerSdp);
                }
                catch (Exception e)
                {
                    SignalError(signaling, networkID, ErrorCode.FailedToSetRemoteDescription);
                    throw new NetherNetException("parse answer", e);
                }

                if (desc.Identity is not null)
                {
                    var publicKey = await VerifyServerToken!(ctx, desc.Identity.Assertion.Token, desc.Identity.IdentityProvider.Domain).ConfigureAwait(false)
                        ?? Jwt.ClaimPublicKey(desc.Identity.Assertion.Token, true);
                    try
                    {
                        desc.Identity.Verify(desc, publicKey);
                    }
                    catch (Exception e)
                    {
                        SignalError(signaling, networkID, ErrorCode.IdentityNotAllowed);
                        throw new NetherNetException("verify server identity", e);
                    }
                    conn.PublicKey = publicKey;
                }
                else if (!AllowIdentitylessServer)
                {
                    SignalError(signaling, networkID, ErrorCode.IdentityNotAllowed);
                    throw new NetherNetException("identityless answer SDP not allowed");
                }

                var result = peer.setRemoteDescription(new RTCSessionDescriptionInit
                {
                    type = RTCSdpType.answer,
                    sdp = Peer.SanitizeForPeer(signal.Data),
                });
                if (result != SetDescriptionResultEnum.OK)
                    throw new NetherNetException($"set remote description failed: {result}");

                for (var i = 0; i < desc.RawCandidates.Count; i++)
                    conn.AddRemoteCandidate(desc.RawCandidates[i]);

                _ = HandleConnAsync(conn, notifier);

                await WaitReadyAsync(peer, conn, channelsOpened.Task, ctx).ConfigureAwait(false);
                if (peer.sctp is not null)
                    conn.SetMaxSegmentPayload(peer.sctp.maxMessageSize - 1);
                return conn;
            }
        }
        catch
        {
            Stop();
            conn.Close();
            throw;
        }
    }

    private async Task<Signal?> ReadSignalAsync(DialerNotifier notifier, CancellationToken ctx, Conn conn, ISignaling signaling)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ctx, conn.Context, signaling.Context);
        try
        {
            return await notifier.Reader.ReadAsync(linked.Token).ConfigureAwait(false);
        }
        catch (ChannelClosedException)
        {
            return null;
        }
        catch (OperationCanceledException)
        {
            if (conn.Context.IsCancellationRequested)
                throw new NetherNetException("nethernet: connection is closed", conn.ContextCause);
            if (ctx.IsCancellationRequested)
            {
                SignalError(signaling, networkID: conn.NetworkID, ErrorCode.NegotiationTimeoutWaitingForResponse);
                throw new NetherNetException("nethernet: negotiation deadline exceeded");
            }
            throw new NetherNetException("nethernet: signaling is closed", signaling.ContextCause);
        }
    }

    private static async Task HandleConnAsync(Conn conn, DialerNotifier notifier)
    {
        while (true)
        {
            Signal? signal;
            using (var linked = CancellationTokenSource.CreateLinkedTokenSource(conn.Context))
            {
                try
                {
                    signal = await notifier.Reader.ReadAsync(linked.Token).ConfigureAwait(false);
                }
                catch (ChannelClosedException)
                {
                    conn.Close();
                    return;
                }
                catch (OperationCanceledException)
                {
                    return;
                }
            }

            if (signal.Type is SignalType.Candidate or SignalType.Error)
            {
                try
                {
                    conn.HandleSignal(signal);
                }
                catch (Exception)
                {
                    // Mirror the reference implementation, which only logs and continues.
                }
            }
        }
    }

    private static async Task WaitReadyAsync(RTCPeerConnection peer, Conn conn, Task channelsOpened, CancellationToken ctx)
    {
        var deadline = DateTime.UtcNow.AddSeconds(30);
        while (true)
        {
            if (conn.Context.IsCancellationRequested)
                throw new NetherNetException("nethernet: connection is closed", conn.ContextCause);
            if (ctx.IsCancellationRequested)
                throw new NetherNetException("nethernet: negotiation deadline exceeded");
            var state = peer.connectionState;
            if (state is RTCPeerConnectionState.failed or RTCPeerConnectionState.closed)
                throw new NetherNetException($"nethernet: peer connection entered unrecoverable state: {state}");
            if (state == RTCPeerConnectionState.connected && channelsOpened.IsCompleted)
                return;
            if (DateTime.UtcNow > deadline)
                throw new NetherNetException("nethernet: timed out waiting for peer connection");
            await Task.Delay(50, CancellationToken.None).ConfigureAwait(false);
        }
    }

    private void SignalError(ISignaling signaling, string networkID, int code)
    {
        _ = Task.Run(async () =>
        {
            try
            {
                using var cts = new CancellationTokenSource(SignalErrorTimeout);
                await signaling.SignalAsync(cts.Token, new Signal
                {
                    Type = SignalType.Error,
                    Data = code.ToString(),
                    ConnectionID = ConnectionID,
                    NetworkID = networkID,
                }).ConfigureAwait(false);
            }
            catch (Exception)
            {
                // The peer may already be gone; the error signal is best-effort.
            }
        });
    }

    public static ulong RandomUInt64()
    {
        Span<byte> bytes = stackalloc byte[8];
        RandomNumberGenerator.Fill(bytes);
        return BitConverter.ToUInt64(bytes);
    }

    private sealed class DialerNegotiator : INegotiator
    {
        private readonly Action _stop;

        public DialerNegotiator(Action stop) => _stop = stop;

        public void HandleClose(Conn conn) => _stop();
    }

    private sealed class DialerNotifier : INotifier
    {
        private readonly Dialer _dialer;
        private readonly string _networkID;
        private readonly Channel<Signal> _signals = Channel.CreateBounded<Signal>(
            new BoundedChannelOptions(64) { FullMode = BoundedChannelFullMode.DropWrite });

        public DialerNotifier(Dialer dialer, string networkID)
        {
            _dialer = dialer;
            _networkID = networkID;
        }

        public ChannelReader<Signal> Reader => _signals.Reader;

        public bool NotifySignal(Signal signal)
        {
            if (signal.ConnectionID != _dialer.ConnectionID || signal.NetworkID != _networkID)
                return false;
            try
            {
                signal.Validate();
            }
            catch (Exception)
            {
                return false;
            }
            return _signals.Writer.TryWrite(signal);
        }

        public void Complete() => _signals.Writer.TryComplete();
    }
}