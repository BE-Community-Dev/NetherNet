using System.Globalization;
using System.Text.Json.Serialization;

namespace NetherNet.Endpoint;

public static class GameTypes
{
    public const int Survival = 0;
    public const int Creative = 1;
    public const int Adventure = 2;
}

public sealed class Status
{
    [JsonInclude]
    [JsonPropertyName("name")]
    public string ServerName = "";

    [JsonInclude]
    [JsonPropertyName("protocol")]
    public int Protocol;

    [JsonInclude]
    [JsonPropertyName("version")]
    public string Version = "";

    [JsonInclude]
    [JsonPropertyName("level")]
    public string LevelName = "";

    [JsonInclude]
    [JsonPropertyName("players")]
    public int PlayerCount;

    [JsonInclude]
    [JsonPropertyName("maxPlayers")]
    public int MaxPlayerCount;

    [JsonInclude]
    [JsonPropertyName("gameType")]
    public int GameType;

    public byte[] RakNet()
    {
        var gameType = GameType switch
        {
            GameTypes.Survival => "Survival",
            GameTypes.Creative => "Creative",
            GameTypes.Adventure => "Adventure",
            _ => "Unknown",
        };
        var text = string.Format(
            CultureInfo.InvariantCulture,
            "MCPE;{0};{1};{2};{3};{4};{5};{6};{7};{8};19132;19132;0;",
            ServerName, Protocol, Version, PlayerCount, MaxPlayerCount,
            DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), LevelName, gameType, GameType);
        return System.Text.Encoding.UTF8.GetBytes(text);
    }

    public static Status RakNetPongData(byte[] b)
    {
        var text = System.Text.Encoding.UTF8.GetString(b);
        var frag = text.Split(';');
        if (frag.Length < 9)
            throw new NetherNetException($"malformed pong data: {text}");
        if (!int.TryParse(frag[2], NumberStyles.Integer, CultureInfo.InvariantCulture, out var protocol))
            throw new NetherNetException("parse protocol version");
        if (!int.TryParse(frag[4], NumberStyles.Integer, CultureInfo.InvariantCulture, out var playerCount))
            throw new NetherNetException("parse player count");
        if (!int.TryParse(frag[5], NumberStyles.Integer, CultureInfo.InvariantCulture, out var maxPlayerCount))
            throw new NetherNetException("parse max player count");
        var gameType = ParseGameType(frag[8]);
        if (gameType < 0)
            throw new NetherNetException($"invalid game type: \"{frag[8]}\"");
        return new Status
        {
            ServerName = frag[1],
            Protocol = protocol,
            Version = frag[3],
            LevelName = frag[7],
            PlayerCount = playerCount,
            MaxPlayerCount = maxPlayerCount,
            GameType = gameType,
        };
    }

    private static int ParseGameType(string v) => v.Trim().ToLowerInvariant() switch
    {
        "survival" => GameTypes.Survival,
        "creative" => GameTypes.Creative,
        "adventure" => GameTypes.Adventure,
        _ => -1,
    };
}