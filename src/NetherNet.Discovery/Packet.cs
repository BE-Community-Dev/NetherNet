using System.Security.Cryptography;

namespace NetherNet.Discovery;

public static class DiscoveryConstants
{
    public const int MaxPacketPayloadLength = 65535;
}

public abstract class Packet
{
    public abstract ushort ID();

    public abstract void Read(ByteBuf r);

    public abstract void Write(ByteBuf w);
}

public static class PacketCodec
{
    public static byte[] Marshal(Packet pk, ulong senderID)
    {
        var buf = new ByteBuf();
        var header = new Header { PacketID = pk.ID(), SenderID = senderID };
        header.Write(buf);
        pk.Write(buf);

        var body = buf.ToArray();
        var payload = new byte[2 + body.Length];
        payload[0] = (byte)(body.Length + 2);
        payload[1] = (byte)((body.Length + 2) >> 8);
        Array.Copy(body, 0, payload, 2, body.Length);

        var encrypted = DiscoveryCrypto.Encrypt(payload);
        var hash = HMACSHA256.HashData(DiscoveryCrypto.Key, payload);

        var result = new byte[hash.Length + encrypted.Length];
        Array.Copy(hash, 0, result, 0, hash.Length);
        Array.Copy(encrypted, 0, result, hash.Length, encrypted.Length);
        return result;
    }

    public static (Packet Packet, ulong SenderID) Unmarshal(byte[] b)
    {
        if (b.Length < 32) throw new EndOfStreamException();

        var payload = DiscoveryCrypto.Decrypt(b[32..]);
        var checksum = HMACSHA256.HashData(DiscoveryCrypto.Key, payload);
        if (!b.AsSpan(0, 32).SequenceEqual(checksum))
            throw new NetherNetException($"checksum mismatch: {Convert.ToHexString(b, 0, 32)} != {Convert.ToHexString(checksum)}");

        var buf = new ByteBuf(payload);
        buf.Skip(2);
        var header = new Header();
        header.Read(buf);

        Packet pk = header.PacketID switch
        {
            ID.RequestPacket => new RequestPacket(),
            ID.ResponsePacket => new ResponsePacket(),
            ID.MessagePacket => new MessagePacket(),
            _ => throw new NetherNetException($"unknown packet ID: {header.PacketID}"),
        };
        pk.Read(buf);
        if (buf.Length != 0)
            throw new NetherNetException($"unread {buf.Length} bytes");
        return (pk, header.SenderID);
    }

    public static byte[] ReadBytes(ByteBuf r, bool oneByteLength)
    {
        uint n = oneByteLength ? (uint)r.ReadByte() : r.ReadUInt32();
        if (n > DiscoveryConstants.MaxPacketPayloadLength)
            throw new NetherNetException($"invalid length: {n}, max {DiscoveryConstants.MaxPacketPayloadLength}");
        if (n > (uint)r.Length)
            throw new NetherNetException($"invalid length: {n}, remaining {r.Length}");
        return r.ReadBytes((int)n);
    }

    public static void WriteBytes(ByteBuf w, byte[] b, bool oneByteLength)
    {
        if (oneByteLength) w.WriteByte((byte)b.Length);
        else w.WriteUInt32((uint)b.Length);
        w.WriteBytes(b);
    }
}

public static class ID
{
    public const ushort RequestPacket = 0;
    public const ushort ResponsePacket = 1;
    public const ushort MessagePacket = 2;
}

public sealed class Header
{
    public ushort PacketID;
    public ulong SenderID;

    public void Read(ByteBuf r)
    {
        PacketID = r.ReadUInt16();
        SenderID = r.ReadUInt64();
        var pad = r.ReadBytes(8);
        if (pad.Length != 8) throw new NetherNetException($"{pad.Length} != 8");
    }

    public void Write(ByteBuf w)
    {
        w.WriteUInt16(PacketID);
        w.WriteUInt64(SenderID);
        w.WriteBytes(new byte[8]);
    }
}