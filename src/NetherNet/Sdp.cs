using System.Text;

namespace NetherNet;

public sealed class SdpSession
{
    private readonly List<string> _lines = new();

    public static SdpSession Parse(string text)
    {
        var session = new SdpSession();
        var normalized = text.Replace("\r\n", "\n").Replace('\r', '\n');
        foreach (var raw in normalized.Split('\n'))
        {
            if (raw.Length == 0) continue;
            session._lines.Add(raw);
        }
        return session;
    }

    public int FirstMediaIndex
    {
        get
        {
            for (var i = 0; i < _lines.Count; i++)
                if (_lines[i].StartsWith("m=", StringComparison.Ordinal)) return i;
            return -1;
        }
    }

    public int MediaCount
    {
        get
        {
            var n = 0;
            foreach (var line in _lines)
                if (line.StartsWith("m=", StringComparison.Ordinal)) n++;
            return n;
        }
    }

    public IReadOnlyList<string> Lines => _lines;

    private static (string Key, string Value)? ParseAttribute(string line)
    {
        if (!line.StartsWith("a=", StringComparison.Ordinal)) return null;
        var body = line[2..];
        var idx = body.IndexOf(':');
        return idx < 0 ? (body, "") : (body[..idx], body[(idx + 1)..]);
    }

    public bool TryGetSessionAttribute(string key, out string value)
    {
        var firstMedia = FirstMediaIndex;
        var end = firstMedia < 0 ? _lines.Count : firstMedia;
        for (var i = 0; i < end; i++)
        {
            var attr = ParseAttribute(_lines[i]);
            if (attr is { } a && a.Key == key)
            {
                value = a.Value;
                return true;
            }
        }
        value = "";
        return false;
    }

    public bool TryGetMediaAttribute(string key, out string value)
    {
        var firstMedia = FirstMediaIndex;
        if (firstMedia < 0)
        {
            value = "";
            return false;
        }
        for (var i = firstMedia; i < _lines.Count; i++)
        {
            var attr = ParseAttribute(_lines[i]);
            if (attr is { } a && a.Key == key)
            {
                value = a.Value;
                return true;
            }
        }
        value = "";
        return false;
    }

    public List<string> SessionAttributeValues(string key)
    {
        var result = new List<string>();
        var firstMedia = FirstMediaIndex;
        var end = firstMedia < 0 ? _lines.Count : firstMedia;
        for (var i = 0; i < end; i++)
        {
            var attr = ParseAttribute(_lines[i]);
            if (attr is { } a && a.Key == key) result.Add(a.Value);
        }
        return result;
    }

    public List<string> MediaAttributeValues(string key)
    {
        var result = new List<string>();
        var firstMedia = FirstMediaIndex;
        if (firstMedia < 0) return result;
        for (var i = firstMedia; i < _lines.Count; i++)
        {
            var attr = ParseAttribute(_lines[i]);
            if (attr is { } a && a.Key == key) result.Add(a.Value);
        }
        return result;
    }

    public void AddSessionLine(string line)
    {
        var firstMedia = FirstMediaIndex;
        if (firstMedia < 0) _lines.Add(line);
        else _lines.Insert(firstMedia, line);
    }

    public void AddMediaLine(string line) => _lines.Add(line);

    public void SetSessionAttribute(string key, string value)
    {
        var firstMedia = FirstMediaIndex;
        var end = firstMedia < 0 ? _lines.Count : firstMedia;
        for (var i = 0; i < end; i++)
        {
            var attr = ParseAttribute(_lines[i]);
            if (attr is { } a && a.Key == key)
            {
                _lines[i] = $"a={key}:{value}";
                return;
            }
        }
        AddSessionLine($"a={key}:{value}");
    }

    public void SetMediaAttribute(string key, string value)
    {
        var firstMedia = FirstMediaIndex;
        if (firstMedia < 0) return;
        for (var i = firstMedia; i < _lines.Count; i++)
        {
            var attr = ParseAttribute(_lines[i]);
            if (attr is { } a && a.Key == key)
            {
                _lines[i] = $"a={key}:{value}";
                return;
            }
        }
        AddMediaLine($"a={key}:{value}");
    }

    public void RemoveMediaAttribute(string key)
    {
        var firstMedia = FirstMediaIndex;
        if (firstMedia < 0) return;
        for (var i = _lines.Count - 1; i >= firstMedia; i--)
        {
            var attr = ParseAttribute(_lines[i]);
            if (attr is { } a && a.Key == key) _lines.RemoveAt(i);
        }
    }

    public void RemoveSessionAttribute(string key)
    {
        var firstMedia = FirstMediaIndex;
        var end = firstMedia < 0 ? _lines.Count : firstMedia;
        for (var i = end - 1; i >= 0; i--)
        {
            var attr = ParseAttribute(_lines[i]);
            if (attr is { } a && a.Key == key) _lines.RemoveAt(i);
        }
    }

    public override string ToString()
    {
        var b = new StringBuilder();
        foreach (var line in _lines)
        {
            b.Append(line).Append("\r\n");
        }
        return b.ToString();
    }
}