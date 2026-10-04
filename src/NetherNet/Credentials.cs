using System.Text.Json.Serialization;

namespace NetherNet;

public sealed class Credentials
{
    [JsonInclude]
    [JsonPropertyName("ExpirationInSeconds")]
    public int ExpirationInSeconds;

    [JsonInclude]
    [JsonPropertyName("TurnAuthServers")]
    public List<IceServer> IceServers = new();
}

public sealed class IceServer
{
    [JsonInclude]
    [JsonPropertyName("Username")]
    public string Username = "";

    [JsonInclude]
    [JsonPropertyName("Password")]
    public string Password = "";

    [JsonInclude]
    [JsonPropertyName("Urls")]
    public List<string> Urls = new();
}

public enum IceGatherPolicy
{
    All,
    Relay,
}