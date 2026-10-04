namespace NetherNet.Discovery;

public static class GameType
{
    public const int Survival = 0;
    public const int Creative = 1;
    public const int Adventure = 2;
}

public sealed class ServerData
{
    public const byte Version = 7;

    public string ServerName = "";
    public int Protocol;
    public string VersionString = "";
    public string LevelName = "";
    public int GameType;
    public int PlayerCount;
    public int MaxPlayerCount;
    public bool EditorWorld;
    public bool Hardcore;
    public bool AcceptsOnlineAuth;
    public bool AcceptsSelfSignedAuth;
    public string Nonce = "";
    public int ConnectionType;

    public byte[] MarshalBinary()
    {
        var buf = new ByteBuf();
        buf.WriteByte(Version);
        BinaryHelpers.WriteString(buf, ServerName);
        BinaryHelpers.WriteVarint32(buf, Protocol);
        BinaryHelpers.WriteString(buf, VersionString);
        BinaryHelpers.WriteString(buf, LevelName);
        BinaryHelpers.WriteVarint32(buf, PlayerCount);
        BinaryHelpers.WriteVarint32(buf, MaxPlayerCount);
        BinaryHelpers.WriteVarint32(buf, GameType);
        BinaryHelpers.WriteBool(buf, EditorWorld);
        BinaryHelpers.WriteBool(buf, Hardcore);
        BinaryHelpers.WriteBool(buf, AcceptsOnlineAuth);
        BinaryHelpers.WriteBool(buf, AcceptsSelfSignedAuth);
        BinaryHelpers.WriteString(buf, Nonce);
        BinaryHelpers.WriteVarint32(buf, ConnectionType);
        return buf.ToArray();
    }

    public static ServerData UnmarshalBinary(byte[] data)
    {
        var buf = new ByteBuf(data);
        var d = new ServerData();

        var v = buf.ReadByte();
        if (v != Version)
            throw new NetherNetException($"version mismatch: got {v}, want {Version}");
        d.ServerName = BinaryHelpers.ReadString(buf);
        d.Protocol = BinaryHelpers.ReadVarint32(buf);
        d.VersionString = BinaryHelpers.ReadString(buf);
        d.LevelName = BinaryHelpers.ReadString(buf);
        d.PlayerCount = BinaryHelpers.ReadVarint32(buf);
        d.MaxPlayerCount = BinaryHelpers.ReadVarint32(buf);
        d.GameType = BinaryHelpers.ReadVarint32(buf);
        d.EditorWorld = BinaryHelpers.ReadBool(buf);
        d.Hardcore = BinaryHelpers.ReadBool(buf);
        d.AcceptsOnlineAuth = BinaryHelpers.ReadBool(buf);
        d.AcceptsSelfSignedAuth = BinaryHelpers.ReadBool(buf);
        d.Nonce = BinaryHelpers.ReadString(buf);
        d.ConnectionType = BinaryHelpers.ReadVarint32(buf);
        if (buf.Length != 0)
            throw new NetherNetException($"unread {buf.Length} bytes");
        return d;
    }
}