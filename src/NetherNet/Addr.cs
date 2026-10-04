using System.Text;

namespace NetherNet;

public sealed class Addr
{
    public ulong ConnectionID;
    public string NetworkID = "";
    public List<IceCandidate> Candidates = new();
    public IceCandidate? SelectedCandidate;

    public string Network() => "nethernet";

    public override string ToString()
    {
        var b = new StringBuilder();
        b.Append(NetworkID).Append(' ');
        if (ConnectionID != 0)
        {
            b.Append('(').Append(ConnectionID).Append(')');
        }
        if (SelectedCandidate is not null)
        {
            b.Append(' ').Append('(').Append(SelectedCandidate.Address).Append(':').Append(SelectedCandidate.Port).Append(')');
        }
        return b.ToString();
    }
}