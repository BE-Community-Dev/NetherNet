using System.Globalization;
using System.Text.Json;

namespace NetherNet;

public sealed class Description
{
    public IceParameters Ice = new();
    public DtlsParameters Dtls = new();
    public uint MaxMessageSize;
    public IdentityData? Identity;
    public List<IceCandidate> Candidates = new();
    public List<string> RawCandidates = new();
}

public static class DescriptionParser
{
    public static Description ParseDescription(SdpSession d)
    {
        if (d.MediaCount != 1)
            throw new NetherNetException($"unexpected number of media descriptions: {d.MediaCount}, expected 1");

        if (!d.TryGetMediaAttribute("ice-ufrag", out var ufrag))
            throw new NetherNetException("missing ice-ufrag attribute");
        if (!d.TryGetMediaAttribute("ice-pwd", out var pwd))
            throw new NetherNetException("missing ice-pwd attribute");

        string fingerprintAttr;
        if (!d.TryGetMediaAttribute("fingerprint", out fingerprintAttr) && !d.TryGetSessionAttribute("fingerprint", out fingerprintAttr))
            throw new NetherNetException("missing fingerprint attribute");
        var fingerprint = fingerprintAttr.Split(' ');
        if (fingerprint.Length != 2)
            throw new NetherNetException($"invalid fingerprint: {fingerprintAttr}");

        IdentityData? identity = null;
        if (d.TryGetSessionAttribute("identity", out var identityAttr))
        {
            byte[] b;
            try
            {
                b = Convert.FromBase64String(identityAttr);
            }
            catch (FormatException e)
            {
                throw new NetherNetException("decode identity assertion in base64", e);
            }
            try
            {
                identity = IdentityData.Parse(b);
            }
            catch (JsonException e)
            {
                throw new NetherNetException("decode identity assertion", e);
            }
        }

        if (!d.TryGetMediaAttribute("setup", out var setup))
            throw new NetherNetException("missing setup attribute");
        var role = setup switch
        {
            "active" => DtlsRole.Client,
            "passive" => DtlsRole.Server,
            "actpass" => DtlsRole.Auto,
            _ => throw new NetherNetException($"invalid setup attribute: {setup}"),
        };

        if (!d.TryGetMediaAttribute("max-message-size", out var maxMessageSizeAttr))
            throw new NetherNetException("missing max-message-size attribute");
        if (!uint.TryParse(maxMessageSizeAttr, NumberStyles.None, CultureInfo.InvariantCulture, out var maxMessageSize))
            throw new NetherNetException($"parse max-message-size attribute as uint32: {maxMessageSizeAttr}");
        if (maxMessageSize <= 1)
            throw new NetherNetException($"max-message-size attribute must exceed one byte: {maxMessageSize}");

        var candidates = new List<IceCandidate>();
        var rawCandidates = new List<string>();
        foreach (var value in d.SessionAttributeValues("candidate"))
        {
            candidates.Add(IceCandidateParser.ParseRemoteCandidate(value));
            rawCandidates.Add(value);
        }
        foreach (var value in d.MediaAttributeValues("candidate"))
        {
            candidates.Add(IceCandidateParser.ParseRemoteCandidate(value));
            rawCandidates.Add(value);
        }

        return new Description
        {
            Ice = new IceParameters { UsernameFragment = ufrag, Password = pwd },
            Dtls = new DtlsParameters
            {
                Role = role,
                Fingerprints =
                {
                    new DtlsFingerprint { Algorithm = fingerprint[0], Value = fingerprint[1] },
                },
            },
            MaxMessageSize = maxMessageSize,
            Identity = identity,
            Candidates = candidates,
            RawCandidates = rawCandidates,
        };
    }
}