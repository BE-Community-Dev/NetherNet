namespace NetherNet;

public interface ISignaling
{
    Task SignalAsync(CancellationToken ctx, Signal signal);

    Action Notify(INotifier n);

    CancellationToken Context { get; }

    Exception? ContextCause { get; }

    Task<Credentials?> CredentialsAsync(CancellationToken ctx);

    string NetworkID();

    void PongData(byte[] b);
}

public interface INotifier
{
    bool NotifySignal(Signal signal);
}

public interface ITrickleIceDisabler
{
    bool DisableTrickleICE();
}

public static class SignalingExtensions
{
    public static bool ShouldDisableTrickleIce(bool configValue, ISignaling signaling)
    {
        if (signaling is ITrickleIceDisabler d)
            return configValue || d.DisableTrickleICE();
        return configValue;
    }
}