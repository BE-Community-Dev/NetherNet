using System.Text;

namespace NetherNet.Discovery;

public sealed class RequestPacket : Packet
{
    public override ushort ID() => Discovery.ID.RequestPacket;

    public override void Read(ByteBuf r) { }

    public override void Write(ByteBuf w) { }
}

public sealed class ResponsePacket : Packet
{
    public byte[] ApplicationData = Array.Empty<byte>();

    public override ushort ID() => Discovery.ID.ResponsePacket;

    public override void Read(ByteBuf r)
    {
        var data = PacketCodec.ReadBytes(r, false);
        try
        {
            ApplicationData = Convert.FromHexString(Encoding.ASCII.GetString(data));
        }
        catch (FormatException e)
        {
            throw new NetherNetException("decode application data", e);
        }
    }

    public override void Write(ByteBuf w)
    {
        var hex = Convert.ToHexString(ApplicationData).ToLowerInvariant();
        PacketCodec.WriteBytes(w, Encoding.ASCII.GetBytes(hex), false);
    }
}

public sealed class MessagePacket : Packet
{
    public ulong RecipientID;
    public string Data = "";

    public override ushort ID() => Discovery.ID.MessagePacket;

    public override void Read(ByteBuf r)
    {
        RecipientID = r.ReadUInt64();
        var data = PacketCodec.ReadBytes(r, false);
        if (r.Length > 0)
        {
            var rest = r.ReadRemaining();
            var combined = new byte[data.Length + rest.Length];
            Array.Copy(data, combined, data.Length);
            Array.Copy(rest, 0, combined, data.Length, rest.Length);
            data = combined;
        }
        Data = Encoding.UTF8.GetString(data);
    }

    public override void Write(ByteBuf w)
    {
        w.WriteUInt64(RecipientID);
        PacketCodec.WriteBytes(w, Encoding.UTF8.GetBytes(Data), false);
    }
}