using System.Buffers.Binary;
using System.Text;

namespace NetherNet.Discovery;

public sealed class ByteBuf
{
    private readonly List<byte> _data;
    private int _pos;

    public ByteBuf() => _data = new List<byte>();

    public ByteBuf(byte[] data) => _data = new List<byte>(data);

    public int Length => _data.Count - _pos;

    public int ReadByte()
    {
        if (_pos >= _data.Count) throw new EndOfStreamException();
        return _data[_pos++];
    }

    public ushort ReadUInt16()
    {
        var b = ReadBytes(2);
        return BinaryPrimitives.ReadUInt16LittleEndian(b);
    }

    public uint ReadUInt32()
    {
        var b = ReadBytes(4);
        return BinaryPrimitives.ReadUInt32LittleEndian(b);
    }

    public ulong ReadUInt64()
    {
        var b = ReadBytes(8);
        return BinaryPrimitives.ReadUInt64LittleEndian(b);
    }

    public byte[] ReadBytes(int n)
    {
        if (n < 0 || _pos + n > _data.Count) throw new EndOfStreamException();
        var result = _data.GetRange(_pos, n).ToArray();
        _pos += n;
        return result;
    }

    public byte[] ReadRemaining()
    {
        var result = _data.GetRange(_pos, _data.Count - _pos).ToArray();
        _pos = _data.Count;
        return result;
    }

    public void Skip(int n)
    {
        if (_pos + n > _data.Count) throw new EndOfStreamException();
        _pos += n;
    }

    public void WriteByte(byte b) => _data.Add(b);

    public void WriteUInt16(ushort v)
    {
        Span<byte> buffer = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(buffer, v);
        _data.AddRange(buffer.ToArray());
    }

    public void WriteUInt32(uint v)
    {
        Span<byte> buffer = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(buffer, v);
        _data.AddRange(buffer.ToArray());
    }

    public void WriteUInt64(ulong v)
    {
        Span<byte> buffer = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(buffer, v);
        _data.AddRange(buffer.ToArray());
    }

    public void WriteBytes(byte[] b) => _data.AddRange(b);

    public byte[] ToArray() => _data.ToArray();
}

public static class BinaryHelpers
{
    public static void WriteBool(ByteBuf buf, bool v) => buf.WriteByte(v ? (byte)1 : (byte)0);

    public static bool ReadBool(ByteBuf buf) => buf.ReadByte() != 0;

    public static void WriteString(ByteBuf buf, string s)
    {
        WriteVaruint32(buf, (uint)Encoding.UTF8.GetByteCount(s));
        buf.WriteBytes(Encoding.UTF8.GetBytes(s));
    }

    public static string ReadString(ByteBuf buf)
    {
        var length = ReadVaruint32(buf);
        if (length > buf.Length)
            throw new NetherNetException($"string length {length} exceeds remaining {buf.Length} bytes");
        return Encoding.UTF8.GetString(buf.ReadBytes((int)length));
    }

    public static void WriteVarint32(ByteBuf buf, int v)
    {
        var u = (uint)v << 1;
        if (v < 0) u = ~u;
        WriteVaruint32(buf, u);
    }

    public static int ReadVarint32(ByteBuf buf)
    {
        var u = ReadVaruint32(buf);
        var v = (int)(u >> 1);
        if ((u & 1) != 0) v = ~v;
        return v;
    }

    public static void WriteVaruint32(ByteBuf buf, uint v)
    {
        while (v >= 0x80)
        {
            buf.WriteByte((byte)(v | 0x80));
            v >>= 7;
        }
        buf.WriteByte((byte)v);
    }

    public static uint ReadVaruint32(ByteBuf buf)
    {
        var v = 0u;
        for (var i = 0u; i < 35; i += 7)
        {
            var b = buf.ReadByte();
            v |= (uint)(b & 0x7f) << (int)i;
            if ((b & 0x80) == 0) return v;
        }
        throw new NetherNetException("varuint32 did not terminate after 5 bytes");
    }
}