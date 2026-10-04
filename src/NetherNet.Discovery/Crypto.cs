using System.Buffers.Binary;
using System.Security.Cryptography;

namespace NetherNet.Discovery;

internal static class DiscoveryCrypto
{
    public static readonly byte[] Key = ComputeKey();

    private static byte[] ComputeKey()
    {
        Span<byte> appId = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(appId, 0xdeadbeef);
        return SHA256.HashData(appId);
    }

    public static byte[] Encrypt(byte[] src)
    {
        using var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = Key;
        aes.IV = new byte[16];
        using var encryptor = aes.CreateEncryptor();
        return encryptor.TransformFinalBlock(src, 0, src.Length);
    }

    public static byte[] Decrypt(byte[] src)
    {
        if (src.Length == 0 || src.Length % 16 != 0)
            throw new NetherNetException($"invalid ciphertext length: {src.Length}");
        using var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = Key;
        aes.IV = new byte[16];
        using var decryptor = aes.CreateDecryptor();
        try
        {
            return decryptor.TransformFinalBlock(src, 0, src.Length);
        }
        catch (CryptographicException e)
        {
            throw new NetherNetException("unpad", e);
        }
    }
}