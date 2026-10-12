namespace BeszelAgentManager.Core.Updates;

public static class PinnedUpdateTrust
{
    // Initial trust comes only from the installed assembly. No external path,
    // configuration override or downloaded root may replace this bootstrap.
    public static TufTrustState Bootstrap()
    {
        using var stream = typeof(PinnedUpdateTrust).Assembly.GetManifestResourceStream(
            "BeszelAgentManager.UpdateRoot")
            ?? throw new InvalidOperationException("Embedded update root is missing.");
        if (stream.Length is <= 0 or > TufJson.MaximumMetadataBytes)
            throw new InvalidOperationException("Embedded update root size is invalid.");
        var bytes = new byte[checked((int)stream.Length)];
        stream.ReadExactly(bytes);
        return TufUpdateVerifier.Bootstrap(bytes);
    }
}
