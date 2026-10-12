using System.Net;

namespace BeszelAgentManager.Core.Updates;

// Transport is not trust: every returned byte still requires metadata verification.
// No URL, filesystem path, credentials or commands are supplied by pipe callers.
public sealed class OfficialUpdateTransport : IDisposable
{
    private readonly HttpClient _http;
    private static readonly TimeSpan MetadataTimeout = TimeSpan.FromSeconds(45);

    public OfficialUpdateTransport() : this(new SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        AutomaticDecompression = DecompressionMethods.None,
        UseCookies = false,
        Credentials = null,
        ConnectTimeout = TimeSpan.FromSeconds(15),
    }) { }

    // Test handlers must not follow redirects; production always constructs above.
    internal OfficialUpdateTransport(HttpMessageHandler handler)
    {
        _http = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("BeszelAgentManager-SignedUpdates/1");
    }

    public Task<byte[]> FetchMetadataAsync(string filename, string? releaseTag = null,
        CancellationToken cancellationToken = default)
    {
        if (!IsMetadataName(filename)) throw new UpdateMetadataException("Unexpected update metadata filename.");
        if (releaseTag is not null && !TufUpdateVerifier.IsValidTag(releaseTag))
            throw new UpdateMetadataException("Invalid metadata release identity.");
        var path = releaseTag is null ? "latest/download" : $"download/{releaseTag}";
        return FetchAsync(new Uri($"https://github.com/{TufUpdateVerifier.Repository}/releases/{path}/{filename}"),
            cancellationToken);
    }

    public async Task<string?> SelectMetadataReleaseAsync(bool includePrereleases, CancellationToken cancellationToken)
    {
        if (!includePrereleases) return null; // Fixed stable/latest download endpoint.
        var bytes = await FetchAsync(new Uri($"https://api.github.com/repos/{TufUpdateVerifier.Repository}/releases?per_page=20"), cancellationToken);
        var releases = TufJson.Parse(bytes);
        if (releases.ValueKind != System.Text.Json.JsonValueKind.Array) throw new UpdateMetadataException("Invalid official release list.");
        string? best = null;
        foreach (var release in releases.EnumerateArray())
        {
            if (!release.TryGetProperty("draft", out var draft) || draft.ValueKind != System.Text.Json.JsonValueKind.False
                || !release.TryGetProperty("tag_name", out var tagElement) || tagElement.ValueKind != System.Text.Json.JsonValueKind.String)
                continue;
            var tag = tagElement.GetString()!;
            if (TufUpdateVerifier.IsValidTag(tag) && (best is null || SecureVersionPolicy.IsSameOrNewer(tag, best))) best = tag;
        }
        return best ?? throw new UpdateMetadataException("No valid official manager release found.");
    }

    public async Task DownloadInstallerAsync(ManagerUpdateTarget target, Stream destination, CancellationToken cancellationToken)
    {
        var expectedName = target.Edition switch
        {
            "bundled" => "BeszelAgentManagerSetup.exe", "lite" => "BeszelAgentManagerSetup-Lite.exe",
            _ => throw new UpdateMetadataException("Invalid installer edition."),
        };
        if (target.Filename != expectedName || !TufUpdateVerifier.IsValidTag(target.Tag)
            || target.Length is <= 0 or > TufUpdateVerifier.MaximumInstallerBytes)
            throw new UpdateMetadataException("Invalid signed installer identity.");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromMinutes(12));
        var uri = target.DownloadUri;
        for (var redirects = 0; ; redirects++)
        {
            ValidateDestination(uri);
            using var response = await _http.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
            if ((int)response.StatusCode is 301 or 302 or 303 or 307 or 308)
            {
                if (redirects >= 3 || response.Headers.Location is null) throw new UpdateMetadataException("Invalid installer redirect.");
                uri = new Uri(uri, response.Headers.Location); continue;
            }
            response.EnsureSuccessStatusCode();
            if (response.Content.Headers.ContentEncoding.Count != 0
                || response.Content.Headers.ContentLength is { } advertised && advertised != target.Length)
                throw new UpdateMetadataException("Installer response differs from signed metadata.");
            await using var input = await response.Content.ReadAsStreamAsync(deadline.Token);
            var buffer = new byte[65536];
            long count = 0;
            while (true)
            {
                var read = await input.ReadAsync(buffer, deadline.Token);
                if (read == 0) break;
                count += read;
                if (count > target.Length) throw new UpdateMetadataException("Installer exceeds signed size.");
                await destination.WriteAsync(buffer.AsMemory(0, read), deadline.Token);
            }
            if (count != target.Length) throw new UpdateMetadataException("Installer download was truncated.");
            return;
        }
    }

    private async Task<byte[]> FetchAsync(Uri uri, CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(MetadataTimeout);
        for (var redirects = 0; ; redirects++)
        {
            ValidateDestination(uri);
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
            if (response.StatusCode is HttpStatusCode.MovedPermanently or HttpStatusCode.Found
                or HttpStatusCode.SeeOther or HttpStatusCode.TemporaryRedirect or HttpStatusCode.PermanentRedirect)
            {
                if (redirects >= 3 || response.Headers.Location is null)
                    throw new UpdateMetadataException("Update download redirect limit or location is invalid.");
                uri = new Uri(uri, response.Headers.Location);
                continue;
            }
            response.EnsureSuccessStatusCode();
            if (response.Content.Headers.ContentEncoding.Count != 0)
                throw new UpdateMetadataException("Encoded update metadata is not accepted.");
            var advertisedLength = response.Content.Headers.ContentLength;
            if (advertisedLength is <= 0 or > TufJson.MaximumMetadataBytes)
                throw new UpdateMetadataException("Update metadata size is outside the allowed range.");
            await using var input = await response.Content.ReadAsStreamAsync(deadline.Token);
            using var output = new MemoryStream();
            var buffer = new byte[8192];
            while (true)
            {
                var count = await input.ReadAsync(buffer, deadline.Token);
                if (count == 0) break;
                if (output.Length + count > TufJson.MaximumMetadataBytes)
                    throw new UpdateMetadataException("Update metadata exceeds the allowed size.");
                output.Write(buffer, 0, count);
            }
            if (output.Length == 0 || advertisedLength is not null && output.Length != advertisedLength)
                throw new UpdateMetadataException("Update metadata download is empty or truncated.");
            return output.ToArray();
        }
    }

    private static void ValidateDestination(Uri uri)
    {
        if (!uri.IsAbsoluteUri || uri.Scheme != Uri.UriSchemeHttps || uri.Port != 443
            || uri.UserInfo.Length != 0 || uri.Fragment.Length != 0)
            throw new UpdateMetadataException("Update download destination is not permitted.");
        if (uri.IdnHost == "release-assets.githubusercontent.com") return;
        if (uri.IdnHost == "api.github.com" && uri.AbsolutePath == $"/repos/{TufUpdateVerifier.Repository}/releases"
            && uri.Query == "?per_page=20") return;
        // GitHub may redirect latest to an exact release, but never another repo.
        var prefix = $"/{TufUpdateVerifier.Repository}/releases/";
        if (uri.IdnHost != "github.com" || !uri.AbsolutePath.StartsWith(prefix, StringComparison.Ordinal)
            || uri.Query.Length != 0)
            throw new UpdateMetadataException("Update download host or repository is not permitted.");
        var rest = uri.AbsolutePath[prefix.Length..].Split('/');
        if (rest.Length != 3 || !(IsMetadataName(rest[2]) || rest[2] is "BeszelAgentManagerSetup.exe" or "BeszelAgentManagerSetup-Lite.exe")
            || !(rest[0] == "latest" && rest[1] == "download"
                || rest[0] == "download" && TufUpdateVerifier.IsValidTag(rest[1])))
            throw new UpdateMetadataException("Update download path is not permitted.");
    }

    private static bool IsMetadataName(string name)
    {
        if (name is "timestamp.json" or "snapshot.json" or "targets.json") return true;
        if (!name.EndsWith(".root.json", StringComparison.Ordinal)) return false;
        var number = name[..^10];
        return number.Length is > 0 and <= 19 && number[0] != '0'
            && number.All(c => c is >= '0' and <= '9')
            && long.TryParse(number, out var version) && version > 0;
    }

    public void Dispose() => _http.Dispose();
}
