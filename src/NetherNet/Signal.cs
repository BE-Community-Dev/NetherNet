using System.Globalization;
using System.Text;

namespace NetherNet;

public static class SignalType
{
    public const string Offer = "CONNECTREQUEST";
    public const string Answer = "CONNECTRESPONSE";
    public const string Candidate = "CANDIDATEADD";
    public const string Error = "CONNECTERROR";
}

public static class ErrorCode
{
    public const int None = 0;
    public const int DestinationNotLoggedIn = 1;
    public const int NegotiationTimeout = 2;
    public const int WrongTransportVersion = 3;
    public const int FailedToCreatePeerConnection = 4;
    public const int Ice = 5;
    public const int ConnectRequest = 6;
    public const int ConnectResponse = 7;
    public const int CandidateAdd = 8;
    public const int InactivityTimeout = 9;
    public const int FailedToCreateOffer = 10;
    public const int FailedToCreateAnswer = 11;
    public const int FailedToSetLocalDescription = 12;
    public const int FailedToSetRemoteDescription = 13;
    public const int NegotiationTimeoutWaitingForResponse = 14;
    public const int NegotiationTimeoutWaitingForAccept = 15;
    public const int IncomingConnectionIgnored = 16;
    public const int SignalingParsingFailure = 17;
    public const int SignalingUnknownError = 18;
    public const int SignalingUnicastMessageDeliveryFailed = 19;
    public const int SignalingBroadcastDeliveryFailed = 20;
    public const int SignalingMessageDeliveryFailed = 21;
    public const int SignalingTurnAuthFailed = 22;
    public const int SignalingFallbackToBestEffortDelivery = 23;
    public const int NoSignalingChannel = 24;
    public const int NotLoggedIn = 25;
    public const int SignalingFailedToSend = 26;
    public const int RelayServerConfigurationResultFailure = 27;
    public const int RelayServerConfigurationResultParsingErrorNoURLs = 28;
    public const int RelayServerConfigurationResultParsingErrorNoCreds = 29;
    public const int RelayServerConfigurationResultParsingErrorNoServers = 30;
    public const int RelayServerConfigurationResultParsingErrorNoExpiration = 31;
    public const int DataChannelClosed = 32;
    public const int InternalErrorJsonSerialization = 33;
    public const int InvalidArgument = 34;
    public const int GenericFailure = 35;
    public const int FailedToCreateIdentityAssertion = 36;
    public const int IdentityNotAllowed = 37;
}

public class NetherNetException : Exception
{
    public NetherNetException(string message) : base(message) { }
    public NetherNetException(string message, Exception? inner) : base(message, inner) { }
}

public sealed class SignalException : NetherNetException
{
    public int Code { get; }

    public SignalException(int code, string message) : base(message)
    {
        Code = code;
    }

    public SignalException(int code, string message, Exception inner) : base(message, inner)
    {
        Code = code;
    }

    public override string ToString() => $"nethernet: {Message} [signaling with code {Code}]";
}

public static class SignalErrors
{
    public static Exception Wrap(Exception err, int code)
    {
        if (err is SignalException) return err;
        return new SignalException(code, err.Message, err);
    }
}

public sealed class Signal
{
    public string Type = "";
    public ulong ConnectionID;
    public string Data = "";
    public string NetworkID = "";

    public static Signal Parse(string text)
    {
        var segments = SplitN(text, ' ', 3);
        if (segments.Length != 3)
            throw new NetherNetException($"unexpected segmentations: {segments.Length}");

        var signal = new Signal
        {
            Type = segments[0],
            Data = segments[2],
        };
        if (!ulong.TryParse(DecimalPrefix(segments[1], false), NumberStyles.None, CultureInfo.InvariantCulture, out signal.ConnectionID))
            throw new NetherNetException("parse ConnectionID: invalid syntax");
        signal.Validate();
        return signal;
    }

    public void Validate()
    {
        switch (Type)
        {
            case SignalType.Offer:
            case SignalType.Answer:
            case SignalType.Candidate:
                return;
            case SignalType.Error:
                ParseSignalErrorCode(Data);
                return;
            default:
                throw new NetherNetException($"unknown signal type: {Type}");
        }
    }

    public static long ParseSignalErrorCode(string data)
    {
        var prefix = DecimalPrefix(data, true);
        if (!long.TryParse(prefix, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var v) || v < int.MinValue || v > int.MaxValue)
            throw new NetherNetException($"parse error code: {data}");
        return v;
    }

    internal static string DecimalPrefix(string s, bool signed)
    {
        var i = 0;
        if (signed && s.Length > 0 && s[0] == '-') i++;
        while (i < s.Length && s[i] >= '0' && s[i] <= '9') i++;
        return s[..i];
    }

    private static string[] SplitN(string s, char separator, int n)
    {
        var parts = new List<string>(n);
        var start = 0;
        while (parts.Count < n - 1)
        {
            var idx = s.IndexOf(separator, start);
            if (idx < 0) break;
            parts.Add(s[start..idx]);
            start = idx + 1;
        }
        parts.Add(s[start..]);
        return parts.ToArray();
    }

    public override string ToString()
    {
        var b = new StringBuilder();
        b.Append(Type).Append(' ').Append(ConnectionID.ToString(CultureInfo.InvariantCulture)).Append(' ').Append(Data);
        return b.ToString();
    }
}