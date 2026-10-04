using System.Globalization;
using System.Text;

namespace NetherNet;

public enum IceProtocol
{
    Udp,
    Tcp,
}

public enum IceCandidateType
{
    Host,
    Srflx,
    Prflx,
    Relay,
}

public static class IceCandidateExtensions
{
    public static string ToShortString(this IceProtocol protocol) => protocol switch
    {
        IceProtocol.Udp => "udp",
        IceProtocol.Tcp => "tcp",
        _ => "unknown",
    };

    public static string ToStringLower(this IceCandidateType type) => type switch
    {
        IceCandidateType.Host => "host",
        IceCandidateType.Srflx => "srflx",
        IceCandidateType.Prflx => "prflx",
        IceCandidateType.Relay => "relay",
        _ => "unknown",
    };

    public static IceProtocol ParseProtocol(string value) => value switch
    {
        "udp" => IceProtocol.Udp,
        "tcp" => IceProtocol.Tcp,
        _ => throw new NetherNetException($"parse ICE protocol: unsupported protocol \"{value}\""),
    };

    public static IceCandidateType ParseType(string value) => value switch
    {
        "host" => IceCandidateType.Host,
        "srflx" => IceCandidateType.Srflx,
        "prflx" => IceCandidateType.Prflx,
        "relay" => IceCandidateType.Relay,
        _ => throw new NetherNetException($"parse ICE candidate type: unsupported type \"{value}\""),
    };
}

public sealed class IceCandidate
{
    public string Foundation = "";
    public uint Priority;
    public string Address = "";
    public IceProtocol Protocol;
    public ushort Port;
    public ushort Component = 1;
    public IceCandidateType Typ;
    public string TcpType = "";
    public string RelatedAddress = "";
    public ushort RelatedPort;
}

public static class IceCandidateParser
{
    public static IceCandidate ParseRemoteCandidate(string data)
    {
        var s = data.Trim();
        if (s.StartsWith("a=", StringComparison.Ordinal)) s = s[2..];
        if (s.StartsWith("candidate:", StringComparison.Ordinal)) s = s["candidate:".Length..];

        var parts = s.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var candidate = new IceCandidate();
        var i = 0;

        if (i < parts.Length) candidate.Foundation = parts[i++];
        if (i < parts.Length && ushort.TryParse(parts[i], NumberStyles.None, CultureInfo.InvariantCulture, out var component))
        {
            candidate.Component = component;
            i++;
        }
        if (i < parts.Length) candidate.Protocol = IceCandidateExtensions.ParseProtocol(parts[i++]);
        if (i < parts.Length && uint.TryParse(parts[i], NumberStyles.None, CultureInfo.InvariantCulture, out var priority))
        {
            candidate.Priority = priority;
            i++;
        }
        if (i < parts.Length) candidate.Address = parts[i++];
        if (i < parts.Length && ushort.TryParse(parts[i], NumberStyles.None, CultureInfo.InvariantCulture, out var port))
        {
            candidate.Port = port;
            i++;
        }
        if (i < parts.Length && parts[i++] == "typ" && i < parts.Length)
            candidate.Typ = IceCandidateExtensions.ParseType(parts[i++]);

        while (i < parts.Length)
        {
            switch (parts[i])
            {
                case "raddr":
                    if (i + 1 < parts.Length) candidate.RelatedAddress = parts[++i];
                    i++;
                    break;
                case "rport":
                    if (i + 1 < parts.Length && ushort.TryParse(parts[i + 1], NumberStyles.None, CultureInfo.InvariantCulture, out var rport))
                        candidate.RelatedPort = rport;
                    i += 2;
                    break;
                case "tcptype":
                    if (i + 1 < parts.Length) candidate.TcpType = parts[++i];
                    i++;
                    break;
                default:
                    i++;
                    break;
            }
        }
        return candidate;
    }

    public static string FormatIceCandidate(int id, IceCandidate candidate, IceParameters iceParams)
    {
        var b = new StringBuilder();
        b.Append("candidate:").Append(candidate.Foundation).Append(' ').Append('1').Append(' ');
        b.Append(candidate.Protocol.ToShortString()).Append(' ');
        b.Append(candidate.Priority.ToString(CultureInfo.InvariantCulture)).Append(' ');
        b.Append(candidate.Address).Append(' ');
        b.Append(candidate.Port.ToString(CultureInfo.InvariantCulture)).Append(' ');
        b.Append("typ ").Append(candidate.Typ.ToStringLower()).Append(' ');
        if (candidate.Typ is IceCandidateType.Relay or IceCandidateType.Srflx)
        {
            b.Append("raddr ").Append(candidate.RelatedAddress).Append(' ')
                .Append("rport ").Append(candidate.RelatedPort.ToString(CultureInfo.InvariantCulture)).Append(' ');
        }
        b.Append("generation 0 ufrag ").Append(iceParams.UsernameFragment).Append(' ');
        b.Append("network-id ").Append(id.ToString(CultureInfo.InvariantCulture)).Append(' ');
        b.Append("network-cost 0");
        return b.ToString();
    }
}

public sealed class IceParameters
{
    public string UsernameFragment = "";
    public string Password = "";
}

public sealed class DtlsFingerprint
{
    public string Algorithm = "";
    public string Value = "";
}

public enum DtlsRole
{
    Auto,
    Client,
    Server,
}

public sealed class DtlsParameters
{
    public DtlsRole Role = DtlsRole.Auto;
    public List<DtlsFingerprint> Fingerprints = new();
}