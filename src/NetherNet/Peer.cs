using System.Text;
using SIPSorcery.Net;

namespace NetherNet;

internal static class Peer
{
    public static RTCConfiguration BuildConfiguration(Credentials? credentials, IceGatherPolicy policy)
    {
        var config = new RTCConfiguration
        {
            iceServers = new List<RTCIceServer>(),
            X_ICEIncludeAllInterfaceAddresses = true,
        };
        if (policy == IceGatherPolicy.Relay)
            config.iceTransportPolicy = RTCIceTransportPolicy.relay;

        if (credentials is not null && credentials.IceServers.Count > 0)
        {
            foreach (var server in credentials.IceServers)
            {
                foreach (var url in server.Urls)
                {
                    config.iceServers.Add(new RTCIceServer
                    {
                        urls = url,
                        username = server.Username,
                        credential = server.Password,
                        credentialType = RTCIceCredentialType.password,
                    });
                }
            }
        }
        return config;
    }

    public static RTCPeerConnection CreatePeer(RTCConfiguration config) => new(config, 0, null!, false);

    public static async Task<List<string>> GatherCandidatesAsync(RTCPeerConnection peer, TimeSpan timeout, CancellationToken ctx)
    {
        var candidates = new List<string>();
        var done = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        peer.onicecandidate += candidate =>
        {
            if (candidate is null) return;
            lock (candidates) candidates.Add(candidate.ToString());
        };
        peer.onicegatheringstatechange += state =>
        {
            if (state == RTCIceGatheringState.complete) done.TrySetResult(true);
        };

        if (peer.iceGatheringState == RTCIceGatheringState.complete) done.TrySetResult(true);

        try
        {
            await Task.WhenAny(done.Task, Task.Delay(timeout, ctx)).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Gathering timed out; use candidates collected so far.
        }
        lock (candidates) return new List<string>(candidates);
    }

    public static void InjectCandidates(SdpSession sdp, IEnumerable<string> candidates)
    {
        var existing = new HashSet<string>(sdp.MediaAttributeValues("candidate"));
        foreach (var candidate in candidates)
        {
            if (!existing.Add(candidate))
                continue;
            sdp.AddMediaLine("a=candidate:" + candidate);
        }
        if (!sdp.TryGetMediaAttribute("end-of-candidates", out _))
            sdp.AddMediaLine("a=end-of-candidates");
    }

    public static Description ApplyIdentity(SdpSession sdp, Identity identity)
    {
        if (sdp.TryGetMediaAttribute("fingerprint", out var fingerprint))
        {
            var parts = fingerprint.Split(' ');
            if (parts.Length == 2)
                sdp.SetMediaAttribute("fingerprint", parts[0] + " " + parts[1].ToUpperInvariant());
        }

        var desc = DescriptionParser.ParseDescription(sdp);
        identity.Sign(desc);
        sdp.SetSessionAttribute("identity", Convert.ToBase64String(Encoding.UTF8.GetBytes(desc.Identity!.ToJson())));
        return desc;
    }

    public static string SanitizeForPeer(string sdp)
    {
        var session = SdpSession.Parse(sdp);
        session.RemoveSessionAttribute("identity");
        return session.ToString();
    }
}