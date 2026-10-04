using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace NetherNet;

public sealed class Identity
{
    public ECDsa PrivateKey = null!;
    public string Token = "";
    public string Domain = "";

    public void Sign(Description desc)
    {
        var payload = IdentityEncoding.GenerateFingerprints(desc.Dtls.Fingerprints);
        var detached = IdentityEncoding.SignDetachedJws(PrivateKey, payload);
        desc.Identity = new IdentityData
        {
            Assertion = new IdentityAssertion
            {
                Fingerprints = detached,
                Token = Token,
            },
            IdentityProvider = new IdentityProvider
            {
                Domain = Domain,
                Protocol = "default",
            },
        };
    }

    public static Identity GenerateServerIdentity(ECDsa privateKey, string domain)
    {
        var encodedPublicKey = IdentityEncoding.EncodePublicKey(privateKey);
        var now = DateTimeOffset.UtcNow;
        var claims = new JsonObject
        {
            ["exp"] = now.AddMinutes(1).ToUnixTimeSeconds(),
            ["iat"] = now.ToUnixTimeSeconds(),
            ["cpk"] = IdentityEncoding.PublicKeyToJwk(privateKey),
        };
        var payload = Encoding.UTF8.GetBytes(claims.ToJsonString());
        var header = new JsonObject
        {
            ["alg"] = "ES384",
            ["x5u"] = encodedPublicKey,
        };
        var headerBytes = Encoding.UTF8.GetBytes(header.ToJsonString());

        var signingInput = IdentityEncoding.Base64UrlEncode(headerBytes) + "." + IdentityEncoding.Base64UrlEncode(payload);
        var signature = IdentityEncoding.SignEs384(privateKey, Encoding.ASCII.GetBytes(signingInput));
        var token = signingInput + "." + IdentityEncoding.Base64UrlEncode(signature);

        return new Identity
        {
            PrivateKey = privateKey,
            Token = token,
            Domain = domain,
        };
    }
}

public sealed class IdentityData
{
    public IdentityAssertion Assertion = new();
    public IdentityProvider IdentityProvider = new();

    public bool Valid()
    {
        static bool ValidJws(string s) => s != "" && s.Count(c => c == '.') == 2;
        return ValidJws(Assertion.Token) && ValidJws(Assertion.Fingerprints) && IdentityProvider.Protocol == "default";
    }

    public void Verify(Description desc, ECDsa publicKey)
    {
        var payload = IdentityEncoding.GenerateFingerprints(desc.Dtls.Fingerprints);
        IdentityEncoding.VerifyDetachedJws(Assertion.Fingerprints, payload, publicKey);
    }

    public string ToJson()
    {
        var assertionJson = new JsonObject
        {
            ["fingerprints"] = Assertion.Fingerprints,
            ["token"] = Assertion.Token,
        }.ToJsonString();
        return new JsonObject
        {
            ["assertion"] = assertionJson,
            ["idp"] = new JsonObject
            {
                ["domain"] = IdentityProvider.Domain,
                ["protocol"] = IdentityProvider.Protocol,
            },
        }.ToJsonString();
    }

    public static IdentityData Parse(byte[] json)
    {
        var root = JsonNode.Parse(json)?.AsObject() ?? throw new NetherNetException("decode identity assertion: invalid JSON");
        var assertionRaw = root["assertion"]?.GetValue<string>() ?? throw new NetherNetException("decode identity assertion: missing assertion");
        var assertionObj = JsonNode.Parse(assertionRaw)?.AsObject() ?? throw new NetherNetException("decode identity assertion: invalid assertion");
        var idp = root["idp"]?.AsObject() ?? new JsonObject();
        var data = new IdentityData
        {
            Assertion = new IdentityAssertion
            {
                Fingerprints = assertionObj["fingerprints"]?.GetValue<string>() ?? "",
                Token = assertionObj["token"]?.GetValue<string>() ?? "",
            },
            IdentityProvider = new IdentityProvider
            {
                Domain = idp["domain"]?.GetValue<string>() ?? "",
                Protocol = idp["protocol"]?.GetValue<string>() ?? "",
            },
        };
        if (!data.Valid()) throw new NetherNetException("malformed identity attribute");
        return data;
    }
}

public sealed class IdentityAssertion
{
    public string Fingerprints = "";
    public string Token = "";
}

public sealed class IdentityProvider
{
    public string Domain = "";
    public string Protocol = "";
}

public static class IdentityEncoding
{
    public static string Base64UrlEncode(byte[] data) => Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] Base64UrlDecode(string s)
    {
        var padded = s.Replace('-', '+').Replace('_', '/');
        switch (padded.Length % 4)
        {
            case 2: padded += "=="; break;
            case 3: padded += "="; break;
        }
        return Convert.FromBase64String(padded);
    }

    public static byte[] SignEs384(ECDsa key, byte[] data)
    {
        var signature = key.SignData(data, HashAlgorithmName.SHA384);
        var size = (key.KeySize + 7) / 8;
        if (signature.Length != size * 2)
            throw new NetherNetException("unexpected ECDSA signature length");
        return signature;
    }

    public static string SignDetachedJws(ECDsa key, byte[] payload)
    {
        var header = Encoding.UTF8.GetBytes("{\"alg\":\"ES384\"}");
        var signingInput = Base64UrlEncode(header) + "." + Base64UrlEncode(payload);
        var signature = SignEs384(key, Encoding.ASCII.GetBytes(signingInput));
        return Base64UrlEncode(header) + ".." + Base64UrlEncode(signature);
    }

    public static void VerifyDetachedJws(string detached, byte[] payload, ECDsa key)
    {
        var segments = detached.Split('.');
        if (segments.Length != 3)
            throw new NetherNetException("parse fingerprints assertion: invalid compact serialization");
        if (segments[1] != "")
            throw new NetherNetException("parse fingerprints assertion: unexpected inline payload");
        var signingInput = Encoding.ASCII.GetBytes(segments[0] + "." + Base64UrlEncode(payload));
        byte[] signature;
        try
        {
            signature = Base64UrlDecode(segments[2]);
        }
        catch (FormatException e)
        {
            throw new NetherNetException("parse fingerprints assertion: invalid signature encoding", e);
        }
        if (!key.VerifyData(signingInput, signature, HashAlgorithmName.SHA384))
            throw new NetherNetException("verify fingerprints assertion: signature mismatch");
    }

    public static byte[] GenerateFingerprints(List<DtlsFingerprint> fingerprints)
    {
        var b = new StringBuilder();
        b.Append("{\"fingerprint\":[");
        for (var i = 0; i < fingerprints.Count; i++)
        {
            if (i != 0) b.Append(',');
            b.Append("{\"algorithm\":").Append(JsonSerializer.Serialize(fingerprints[i].Algorithm));
            b.Append(",\"digest\":").Append(JsonSerializer.Serialize(fingerprints[i].Value));
            b.Append('}');
        }
        b.Append("]}");
        return Encoding.UTF8.GetBytes(b.ToString());
    }

    public static string EncodePublicKey(ECDsa key)
    {
        if (key is null) throw new NetherNetException("public key is nil");
        return Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());
    }

    public static JsonObject PublicKeyToJwk(ECDsa key)
    {
        var p = key.ExportParameters(false);
        return new JsonObject
        {
            ["kty"] = "EC",
            ["crv"] = "P-384",
            ["x"] = Base64UrlEncode(ToFixed(p.Q.X)),
            ["y"] = Base64UrlEncode(ToFixed(p.Q.Y)),
        };
    }

    private static byte[] ToFixed(byte[]? value) => value ?? Array.Empty<byte>();

    public static ECDsa ParsePublicKey(JsonNode? node)
    {
        if (node is null) throw new NetherNetException("nil cpk claim");
        if (node is JsonObject obj)
        {
            var kty = obj["kty"]?.GetValue<string>();
            var crv = obj["crv"]?.GetValue<string>();
            var x = obj["x"]?.GetValue<string>();
            var y = obj["y"]?.GetValue<string>();
            if (kty != "EC") throw new NetherNetException($"invalid key type: {kty}, expected EC");
            if (crv != "P-384") throw new NetherNetException($"invalid curve: {crv}, expected P-384");
            if (x is null || y is null) throw new NetherNetException("invalid JWK: missing x or y");
            var key = ECDsa.Create(ECCurve.NamedCurves.nistP384);
            key.ImportParameters(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP384,
                Q = new ECPoint
                {
                    X = Base64UrlDecode(x),
                    Y = Base64UrlDecode(y),
                },
            });
            return key;
        }
        if (node is JsonValue value && value.TryGetValue<string>(out var s))
        {
            var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(s), out _);
            return key;
        }
        throw new NetherNetException("invalid JSON value, expected an object or a string");
    }
}

public static class Jwt
{
    public static ECDsa ClaimPublicKey(string token, bool selfSigned)
    {
        var segments = token.Split('.');
        if (segments.Length != 3)
            throw new NetherNetException("parse JWT token: invalid compact serialization");

        JsonObject payload;
        try
        {
            payload = JsonNode.Parse(Base64Url(segments[1]))?.AsObject()
                ?? throw new NetherNetException("extract JWT claims: invalid payload");
        }
        catch (JsonException e)
        {
            throw new NetherNetException("extract JWT claims: invalid JSON", e);
        }

        var publicKey = IdentityEncoding.ParsePublicKey(payload["cpk"]);
        if (!selfSigned)
        {
            ValidateTimeClaims(payload);
        }
        else
        {
            var signingInput = Encoding.ASCII.GetBytes(segments[0] + "." + segments[1]);
            if (!publicKey.VerifyData(signingInput, IdentityEncoding.Base64UrlDecode(segments[2]), HashAlgorithmName.SHA384))
                throw new NetherNetException("verify JWT claims: signature mismatch");
        }
        return publicKey;
    }

    private static byte[] Base64Url(string s) => IdentityEncoding.Base64UrlDecode(s);

    private static void ValidateTimeClaims(JsonObject payload)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (TryGetLong(payload, "exp", out var exp) && now >= exp)
            throw new NetherNetException("validate JWT claims: token has expired");
        if (TryGetLong(payload, "nbf", out var nbf) && now < nbf)
            throw new NetherNetException("validate JWT claims: token is not yet valid");
    }

    private static bool TryGetLong(JsonObject payload, string name, out long value)
    {
        value = 0;
        var node = payload[name];
        if (node is null) return false;
        if (node is JsonValue v)
        {
            if (v.TryGetValue<long>(out value)) return true;
            if (v.TryGetValue<double>(out var d)) { value = (long)d; return true; }
        }
        return false;
    }
}