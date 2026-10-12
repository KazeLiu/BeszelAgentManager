using System.Net;
using BeszelAgentManager.Core.Updates;
using Xunit;

namespace BeszelAgentManager.Core.Tests;

public sealed class OfficialUpdateTransportTests
{
    [Fact]
    public async Task UsesOnlyOfficialFixedMetadataEndpoint()
    {
        using var handler = new Handler((request, _) =>
        {
            Assert.Equal("https://github.com/MiranoVerhoef/BeszelAgentManager/releases/latest/download/timestamp.json",
                request.RequestUri!.AbsoluteUri);
            Assert.Null(request.Headers.Authorization);
            return Task.FromResult(Ok([1, 2, 3]));
        });
        using var transport = new OfficialUpdateTransport(handler);
        Assert.Equal(new byte[] { 1, 2, 3 }, await transport.FetchMetadataAsync("timestamp.json", cancellationToken: TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData("../config.json")]
    [InlineData("root.json")]
    [InlineData("01.root.json")]
    [InlineData("0.root.json")]
    [InlineData("https://evil.test/targets.json")]
    [InlineData("timestamp.json?x=1")]
    public async Task InvalidNamesNeverReachNetwork(string filename)
    {
        using var handler = new Handler((_, _) => throw new Xunit.Sdk.XunitException("Network should not run"));
        using var transport = new OfficialUpdateTransport(handler);
        await Assert.ThrowsAsync<UpdateMetadataException>(() => transport.FetchMetadataAsync(filename, cancellationToken: TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData("http://github.com/MiranoVerhoef/BeszelAgentManager/releases/download/4.21.1/targets.json")]
    [InlineData("https://user:password@release-assets.githubusercontent.com/a")]
    [InlineData("https://127.0.0.1/a")]
    [InlineData("https://github.com/other/repo/releases/download/4.21.1/targets.json")]
    [InlineData("https://release-assets.githubusercontent.com.evil.test/a")]
    [InlineData("https://release-assets.githubusercontent.com:444/a")]
    [InlineData("file:///C:/test")]
    public async Task RejectsUnapprovedRedirectBeforeFollowingIt(string destination)
    {
        var calls = 0;
        using var handler = new Handler((_, _) =>
        {
            calls++;
            var response = new HttpResponseMessage(HttpStatusCode.Found);
            response.Headers.Location = new Uri(destination);
            return Task.FromResult(response);
        });
        using var transport = new OfficialUpdateTransport(handler);
        await Assert.ThrowsAsync<UpdateMetadataException>(() => transport.FetchMetadataAsync("targets.json", cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task FollowsBoundedOfficialAssetRedirects()
    {
        var calls = 0;
        using var handler = new Handler((_, _) =>
        {
            calls++;
            if (calls == 3) return Task.FromResult(Ok([7]));
            var response = new HttpResponseMessage(HttpStatusCode.Found);
            response.Headers.Location = new Uri(calls == 1
                ? "https://github.com/MiranoVerhoef/BeszelAgentManager/releases/download/4.21.1/targets.json"
                : "https://release-assets.githubusercontent.com/fixed-asset?signature=test");
            return Task.FromResult(response);
        });
        using var transport = new OfficialUpdateTransport(handler);
        Assert.Equal(new byte[] { 7 }, await transport.FetchMetadataAsync("targets.json", cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(3, calls);
    }

    [Fact]
    public async Task RedirectLoopIsBounded()
    {
        var calls = 0;
        using var handler = new Handler((request, _) =>
        {
            calls++;
            var response = new HttpResponseMessage(HttpStatusCode.Found);
            response.Headers.Location = request.RequestUri;
            return Task.FromResult(response);
        });
        using var transport = new OfficialUpdateTransport(handler);
        await Assert.ThrowsAsync<UpdateMetadataException>(() => transport.FetchMetadataAsync("targets.json", cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(4, calls);
    }

    [Fact]
    public async Task RejectsOversizeWithoutContentLength()
    {
        using var handler = new Handler((_, _) =>
        {
            var response = Ok(new byte[TufJson.MaximumMetadataBytes + 1]);
            response.Content = new StreamContent(new MemoryStream(new byte[TufJson.MaximumMetadataBytes + 1]));
            return Task.FromResult(response);
        });
        using var transport = new OfficialUpdateTransport(handler);
        await Assert.ThrowsAsync<UpdateMetadataException>(() => transport.FetchMetadataAsync("targets.json", cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task RejectsTruncatedBody()
    {
        using var handler = new Handler((_, _) =>
        {
            var response = Ok([1]);
            response.Content.Headers.ContentLength = 100;
            return Task.FromResult(response);
        });
        using var transport = new OfficialUpdateTransport(handler);
        await Assert.ThrowsAsync<UpdateMetadataException>(() => transport.FetchMetadataAsync("targets.json", cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task CancellationReachesPendingNetworkRequest()
    {
        using var handler = new Handler(async (_, token) =>
        {
            await Task.Delay(Timeout.Infinite, token);
            return Ok([1]);
        });
        using var transport = new OfficialUpdateTransport(handler);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => transport.FetchMetadataAsync("targets.json", cancellationToken: cancellation.Token));
    }

    [Fact]
    public async Task FetchesConsecutiveRootNameAndExactPrerelease()
    {
        using var handler = new Handler((request, _) =>
        {
            Assert.Equal("https://github.com/MiranoVerhoef/BeszelAgentManager/releases/download/4.21.1-rc1/2.root.json",
                request.RequestUri!.AbsoluteUri);
            return Task.FromResult(Ok([1]));
        });
        using var transport = new OfficialUpdateTransport(handler);
        await transport.FetchMetadataAsync("2.root.json", "4.21.1-rc1", TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task RejectsEncodedResponse()
    {
        using var handler = new Handler((_, _) =>
        {
            var response = Ok([1]);
            response.Content.Headers.ContentEncoding.Add("gzip");
            return Task.FromResult(response);
        });
        using var transport = new OfficialUpdateTransport(handler);
        await Assert.ThrowsAsync<UpdateMetadataException>(() => transport.FetchMetadataAsync("targets.json", cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task InvalidTagNeverReachesNetwork()
    {
        using var handler = new Handler((_, _) => throw new Xunit.Sdk.XunitException("Network should not run"));
        using var transport = new OfficialUpdateTransport(handler);
        await Assert.ThrowsAsync<UpdateMetadataException>(() => transport.FetchMetadataAsync("targets.json", "4.21.1/../../other", TestContext.Current.CancellationToken));
    }

    private static HttpResponseMessage Ok(byte[] data) => new(HttpStatusCode.OK) { Content = new ByteArrayContent(data) };
    [Fact]
    public async Task InstallerDownloadUsesSignedEditionAndExactSize()
    {
        using var handler = new Handler((request, _) =>
        {
            Assert.EndsWith("/4.21.1/BeszelAgentManagerSetup-Lite.exe", request.RequestUri!.AbsoluteUri);
            Assert.Null(request.Headers.Authorization);
            return Task.FromResult(Ok([1, 2, 3]));
        });
        using var transport = new OfficialUpdateTransport(handler);
        using var output = new MemoryStream();
        await transport.DownloadInstallerAsync(new ManagerUpdateTarget("4.21.1", "lite", "BeszelAgentManagerSetup-Lite.exe", 3, new string('a', 64)),
            output, TestContext.Current.CancellationToken);
        Assert.Equal(new byte[] { 1, 2, 3 }, output.ToArray());
    }

    [Theory]
    [InlineData(2)]
    [InlineData(4)]
    public async Task InstallerWrongLengthIsRejected(long length)
    {
        using var handler = new Handler((_, _) => Task.FromResult(Ok([1, 2, 3])));
        using var transport = new OfficialUpdateTransport(handler);
        using var output = new MemoryStream();
        await Assert.ThrowsAsync<UpdateMetadataException>(() => transport.DownloadInstallerAsync(
            new ManagerUpdateTarget("4.21.1", "bundled", "BeszelAgentManagerSetup.exe", length, new string('a', 64)),
            output, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task WrongEditionFilenameNeverReachesNetwork()
    {
        using var handler = new Handler((_, _) => throw new Xunit.Sdk.XunitException("Network should not run"));
        using var transport = new OfficialUpdateTransport(handler);
        using var output = new MemoryStream();
        await Assert.ThrowsAsync<UpdateMetadataException>(() => transport.DownloadInstallerAsync(
            new ManagerUpdateTarget("4.21.1", "lite", "BeszelAgentManagerSetup.exe", 3, new string('a', 64)),
            output, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task PrereleaseLookupOrdersRcNumbersAndIgnoresDrafts()
    {
        using var handler = new Handler((request, _) =>
        {
            Assert.Equal("api.github.com", request.RequestUri!.Host);
            return Task.FromResult(Ok(System.Text.Encoding.UTF8.GetBytes(
                """[{"tag_name":"4.21.1-rc9","draft":false},{"tag_name":"4.21.1-rc10","draft":false},{"tag_name":"4.99.0","draft":true}]""")));
        });
        using var transport = new OfficialUpdateTransport(handler);
        Assert.Equal("4.21.1-rc10", await transport.SelectMetadataReleaseAsync(true, TestContext.Current.CancellationToken));
        Assert.Null(await transport.SelectMetadataReleaseAsync(false, TestContext.Current.CancellationToken));
    }
    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => send(request, cancellationToken);
    }
}
