using System.Diagnostics;
using System.Net;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text.Json;
using BeszelAgentManager.Core.Updates;

namespace BeszelAgentManager.Helper.Updates;

[SupportedOSPlatform("windows")]
internal static class SignedManagerUpdateHost
{
    private static string ServiceData => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "BeszelAgentManager.ServiceData");

    internal static async Task<ManagerUpdateStage> PrepareAsync(string authorizedSid, int session, bool prereleases, CancellationToken cancellationToken)
    {
        RequireSystem();
        InstalledManagerIdentity.RequireInstalledHelper();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromMinutes(14));
        var token = timeout.Token;
        using var store = new ProtectedUpdateStore(ServiceData);
        RefuseActiveCommit(store.DirectoryPath);
        using var transport = new OfficialUpdateTransport();
        var releaseTag = await transport.SelectMetadataReleaseAsync(prereleases, token);
        for (var count = 0; count < 64; count++)
        {
            byte[] next;
            try { next = await transport.FetchMetadataAsync($"{checked(store.State.RootVersion + 1)}.root.json", releaseTag, token); }
            catch (HttpRequestException ex) when (ex.StatusCode == HttpStatusCode.NotFound) { break; }
            await store.AcceptRootAsync(next, token);
            if (count == 63) throw new UpdateMetadataException("Root refresh limit reached; further authenticated roots are required.");
        }
        var metadata = new Dictionary<string, byte[]>();
        var installedTag = InstalledManagerIdentity.ReadTag();
        var edition = InstalledManagerIdentity.ReadEdition();
        var verified = await TufRefreshCoordinator.RefreshAsync(store.State,
            async (name, ct) => metadata[name] = await transport.FetchMetadataAsync(name, releaseTag, ct),
            store.SaveCheckpointAsync, edition, installedTag, prereleases, DateTimeOffset.UtcNow, token);
        if (releaseTag is not null && verified.Target.Tag != releaseTag)
            throw new UpdateMetadataException("Signed target does not match the selected latest release.");

        var job = new Job(Guid.NewGuid().ToString("N"), verified.Target.Tag, edition, installedTag,
            authorizedSid, session, prereleases, DateTimeOffset.UtcNow.AddMinutes(30));
        var jobs = Path.Combine(store.DirectoryPath, "jobs");
        SafeSecurityTree.Ensure(jobs, null, setOwner: false);
        // Keep only one staged operation. Committed work is checked above and
        // holds install.lock while executing. No caller chooses a cleanup path.
        using (var jobsPin = PinnedLocalPath.Directory(jobs))
        {
            jobsPin.RequireProtected();
            foreach (var entry in Directory.EnumerateFileSystemEntries(jobs)) SafeFileTree.Delete(entry);
        }
        var directory = Path.Combine(jobs, job.OperationId);
        SafeSecurityTree.Ensure(directory, null, setOwner: false);
        using var jobPin = PinnedLocalPath.Directory(directory);
        jobPin.RequireProtected();
        try
        {
            foreach (var pair in metadata) await WriteNewAsync(Path.Combine(directory, pair.Key), pair.Value, token);
            var installer = Path.Combine(directory, "installer.exe");
            await using (var output = new FileStream(installer, FileMode.CreateNew, FileAccess.Write, FileShare.None, 65536, FileOptions.WriteThrough))
            {
                await transport.DownloadInstallerAsync(verified.Target, output, token);
                output.Flush(true);
            }
            using (var pinned = PinnedLocalPath.File(installer))
            {
                pinned.RequireProtected();
                await using var input = new FileStream(pinned.Handle, FileAccess.Read);
                await TufUpdateVerifier.VerifyInstallerAsync(input, verified.Target, token);
                CheckInstallerVersion(installer, verified.Target.Tag);
            }
            // Download time never extends expired metadata or bypasses the clock floor.
            var final = VerifyJobMetadata(store, directory, job, installedTag);
            await store.SaveCheckpointAsync(final.State, token);
            await CopyWorkerAsync(directory, token);
            await WriteNewAsync(Path.Combine(directory, "job.json"), JsonSerializer.SerializeToUtf8Bytes(job), token);
            ReplaceProtectedJson(Path.Combine(store.DirectoryPath, "active.json"), job);
            return new ManagerUpdateStage(job.OperationId, job.Tag, job.Edition);
        }
        catch
        {
            // Files are in protected storage; no unsafe ownership/ACL fallback.
            throw;
        }
    }

    internal static void Commit(string operationId, string authorizedSid)
    {
        RequireSystem();
        ValidateOperationId(operationId);
        using var store = new ProtectedUpdateStore(ServiceData);
        var job = ReadJson<Job>(Path.Combine(store.DirectoryPath, "active.json"));
        if (job.OperationId != operationId || job.AuthorizedSid != authorizedSid || job.Expires <= DateTimeOffset.UtcNow)
            throw new UpdateMetadataException("Staged operation is missing, expired or belongs to another user.");
        var directory = Path.Combine(store.DirectoryPath, "jobs", operationId);
        using var root = PinnedLocalPath.Directory(directory);
        root.RequireProtected();
        var stagedJob = ReadJson<Job>(Path.Combine(directory, "job.json"));
        if (stagedJob != job) throw new UpdateMetadataException("Staged operation identity differs from active operation.");
        var result = VerifyJobMetadata(store, directory, job, InstalledManagerIdentity.ReadTag());
        using (var installer = PinnedLocalPath.File(Path.Combine(directory, "installer.exe")))
        {
            installer.RequireProtected();
            using var input = new FileStream(installer.Handle, FileAccess.Read);
            TufUpdateVerifier.VerifyInstallerAsync(input, result.Target).GetAwaiter().GetResult();
        }
        WriteNewAsync(Path.Combine(directory, "committed.json"), JsonSerializer.SerializeToUtf8Bytes(new { operation_id = operationId }), CancellationToken.None).GetAwaiter().GetResult();
        var runner = Path.Combine(directory, "runner", "BeszelManagerUpdateWorker.exe");
        using var executable = PinnedLocalPath.File(runner);
        executable.RequireProtected();
        try
        {
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = runner, UseShellExecute = false, CreateNoWindow = true,
                WorkingDirectory = Path.GetDirectoryName(runner)!, ArgumentList = { "--complete-manager-update", operationId },
            }) ?? throw new IOException("Could not start the signed update worker.");
        }
        catch (Exception ex)
        {
            ReplaceProtectedJson(Path.Combine(directory, "result.json"), new { status = "failed", message = ex.Message });
            ReplaceProtectedJson(Path.Combine(store.DirectoryPath, "last-result.json"), new { operation_id = operationId, status = "failed", message = ex.Message });
            throw;
        }
        // Accepted for installation is not a completed/successful upgrade.
    }

    internal static async Task<int> CompleteAsync(string operationId)
    {
        try { return await CompleteCoreAsync(operationId); }
        catch (Exception ex)
        {
            // Startup/expiry/lock failures are also terminal results, not a
            // permanently pending operation. No installer is launched here.
            RequireSystem(); ValidateOperationId(operationId);
            var root = Path.Combine(ServiceData, "secure-manager-updates");
            using var pin = PinnedLocalPath.Directory(root); pin.RequireProtected();
            var directory = Path.Combine(root, "jobs", operationId);
            var job = ReadJson<Job>(Path.Combine(directory, "job.json"));
            ReplaceProtectedJson(Path.Combine(directory, "result.json"), new { status = "failed", message = ex.Message });
            ReplaceProtectedJson(Path.Combine(root, "last-result.json"), new { operation_id = operationId, status = "failed", message = ex.Message });
            try { UserSessionLauncher.Launch(job.Session, job.AuthorizedSid); } catch { }
            return 58;
        }
    }

    private static async Task<int> CompleteCoreAsync(string operationId)
    {
        RequireSystem();
        ValidateOperationId(operationId);
        using var store = new ProtectedUpdateStore(ServiceData);
        var directory = Path.Combine(store.DirectoryPath, "jobs", operationId);
        if (!Path.GetFullPath(AppContext.BaseDirectory).TrimEnd('\\').Equals(Path.Combine(directory, "runner"), StringComparison.OrdinalIgnoreCase))
            throw new IOException("Update worker location is invalid.");
        using var jobRoot = PinnedLocalPath.Directory(directory);
        jobRoot.RequireProtected();
        var job = ReadJson<Job>(Path.Combine(directory, "job.json"));
        if (job.OperationId != operationId || job.Expires <= DateTimeOffset.UtcNow)
            throw new UpdateMetadataException("Update worker operation is expired or invalid.");
        ReadJson<JsonElement>(Path.Combine(directory, "committed.json"));
        var lockPath = Path.Combine(store.DirectoryPath, "install.lock");
        if (File.Exists(lockPath)) { using var check = PinnedLocalPath.File(lockPath); check.RequireProtected(); }
        using var installLock = new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        var status = "failed";
        var message = "Installation did not complete.";
        var exit = 1;
        try
        {
            await Task.Delay(TimeSpan.FromSeconds(3)); // Allow accepted response and normal UI exit.
            var verified = VerifyJobMetadata(store, directory, job, InstalledManagerIdentity.ReadTag());
            var installerPath = Path.Combine(directory, "installer.exe");
            using var installer = PinnedLocalPath.File(installerPath);
            installer.RequireProtected();
            // Borrow the pinned handle without transferring its ownership to
            // FileStream. The same object stays pinned through process execution.
            using var borrowed = new Microsoft.Win32.SafeHandles.SafeFileHandle(installer.Handle.DangerousGetHandle(), ownsHandle: false);
            await using (var input = new FileStream(borrowed, FileAccess.Read))
                await TufUpdateVerifier.VerifyInstallerAsync(input, verified.Target);
            CheckInstallerVersion(installerPath, job.Tag);
            var fresh = VerifyJobMetadata(store, directory, job, InstalledManagerIdentity.ReadTag());
            await store.SaveCheckpointAsync(fresh.State, CancellationToken.None);
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = installerPath, UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = directory,
                ArgumentList = { "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-", "/CLOSEAPPLICATIONS",
                    $"/DIR={InstalledManagerIdentity.Root}", $"/LOG={Path.Combine(directory, "installer.log")}", "/SECUREUPDATE" },
            }) ?? throw new IOException("Could not launch verified installer.");
            using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(15));
            try { await process.WaitForExitAsync(timeout.Token); }
            catch (OperationCanceledException) { process.Kill(entireProcessTree: true); throw new IOException("Installer timed out; inspect installation before retrying."); }
            if (process.ExitCode != 0) throw new IOException($"Installer exited with code {process.ExitCode}.");
            if (InstalledManagerIdentity.ReadTag() != job.Tag || InstalledManagerIdentity.ReadEdition() != job.Edition)
                throw new IOException("Post-install version or edition verification failed.");
            InstalledManagerIdentity.RequireProtectedInstallation();
            InstalledManagerIdentity.VerifyInstalledBinariesAndService(job.Tag);
            using var background = new ServiceController("BeszelAgentManager Background");
            background.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
            status = "completed"; message = $"Installed {job.Tag} ({job.Edition})."; exit = 0;
        }
        catch (Exception ex) { message = ex.Message; }
        ReplaceProtectedJson(Path.Combine(store.DirectoryPath, "last-result.json"), new { operation_id = operationId, status, message, completed_utc = DateTimeOffset.UtcNow });
        ReplaceProtectedJson(Path.Combine(directory, "result.json"), new { status, message });
        try { UserSessionLauncher.Launch(job.Session, job.AuthorizedSid); }
        catch (Exception ex)
        {
            ReplaceProtectedJson(Path.Combine(store.DirectoryPath, "last-result.json"), new
                { operation_id = operationId, status, message, relaunch_error = ex.Message, completed_utc = DateTimeOffset.UtcNow });
        }
        return exit;
    }

    internal static string ReadLastResult()
    {
        using var store = new ProtectedUpdateStore(ServiceData);
        var path = Path.Combine(store.DirectoryPath, "last-result.json");
        return File.Exists(path) ? ReadJson<JsonElement>(path).GetRawText() : "{}";
    }

    private static VerifiedManagerUpdate VerifyJobMetadata(ProtectedUpdateStore store, string directory, Job job, string installedTag)
    {
        if (job.Expires <= DateTimeOffset.UtcNow || InstalledManagerIdentity.ReadEdition() != job.Edition)
            throw new UpdateMetadataException("Staged update expired or edition changed.");
        var verified = TufUpdateVerifier.Verify(store.State, ReadBytes(Path.Combine(directory, "timestamp.json")),
            ReadBytes(Path.Combine(directory, "snapshot.json")), ReadBytes(Path.Combine(directory, "targets.json")),
            job.Edition, installedTag, job.Prereleases, DateTimeOffset.UtcNow);
        if (verified.Target.Tag != job.Tag) throw new UpdateMetadataException("Staged target identity changed.");
        return verified;
    }

    private static async Task CopyWorkerAsync(string directory, CancellationToken token)
    {
        var runner = Path.Combine(directory, "runner");
        SafeSecurityTree.Ensure(runner, null, setOwner: false);
        using var source = PinnedLocalPath.Directory(InstalledManagerIdentity.HelperDirectory);
        source.RequireProtected();
        long total = 0;
        foreach (var file in Directory.EnumerateFiles(source.Path))
        {
            if (file.EndsWith(".pdb", StringComparison.OrdinalIgnoreCase)) continue;
            using var pinned = PinnedLocalPath.File(file);
            pinned.RequireProtected();
            await using var input = new FileStream(pinned.Handle, FileAccess.Read);
            total += input.Length;
            if (total > 250L * 1024 * 1024) throw new IOException("Update worker exceeds staging limit.");
            var name = Path.GetFileName(file) == "BeszelAgentManager.Helper.exe" ? "BeszelManagerUpdateWorker.exe" : Path.GetFileName(file);
            await using var output = new FileStream(Path.Combine(runner, name), FileMode.CreateNew, FileAccess.Write, FileShare.None, 65536, FileOptions.WriteThrough);
            await input.CopyToAsync(output, token); output.Flush(true);
        }
    }

    private static void RefuseActiveCommit(string root)
    {
        var path = Path.Combine(root, "active.json");
        if (!File.Exists(path)) return;
        var job = ReadJson<Job>(path);
        ValidateOperationId(job.OperationId);
        var directory = Path.Combine(root, "jobs", job.OperationId);
        if (File.Exists(Path.Combine(directory, "committed.json")) && !File.Exists(Path.Combine(directory, "result.json")))
            throw new IOException("A committed update is pending. Check the background-service log before retrying.");
    }

    private static void CheckInstallerVersion(string path, string tag)
    {
        var info = FileVersionInfo.GetVersionInfo(path);
        if ($"{info.ProductMajorPart}.{info.ProductMinorPart}.{info.ProductBuildPart}" != tag.Split('-')[0])
            throw new UpdateMetadataException("Installer product version does not match signed target.");
    }

    private static void ValidateOperationId(string value)
    {
        if (!Guid.TryParseExact(value, "N", out _) || value != value.ToLowerInvariant())
            throw new UpdateMetadataException("Invalid update operation ID.");
    }
    private static void RequireSystem()
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (!identity.IsSystem) throw new UnauthorizedAccessException("Signed installation is available only through the background service.");
    }
    private static byte[] ReadBytes(string path)
    {
        using var pinned = PinnedLocalPath.File(path); pinned.RequireProtected();
        using var stream = new FileStream(pinned.Handle, FileAccess.Read);
        if (stream.Length is <= 0 or > TufJson.MaximumMetadataBytes) throw new IOException("Protected update file size is invalid.");
        var bytes = new byte[checked((int)stream.Length)]; stream.ReadExactly(bytes); return bytes;
    }
    private static T ReadJson<T>(string path)
    {
        var bytes = ReadBytes(path);
        _ = TufJson.Parse(bytes);
        return JsonSerializer.Deserialize<T>(bytes) ?? throw new IOException("Invalid protected update record.");
    }
    private static async Task WriteNewAsync(string path, byte[] bytes, CancellationToken token)
    {
        await using var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough);
        await output.WriteAsync(bytes, token); output.Flush(true);
    }
    private static void ReplaceProtectedJson<T>(string path, T record)
    {
        using var parent = PinnedLocalPath.Directory(Path.GetDirectoryName(path)!); parent.RequireProtected();
        if (File.Exists(path)) { using var existing = PinnedLocalPath.File(path); existing.RequireProtected(); }
        var temporary = Path.Combine(parent.Path, Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            WriteNewAsync(temporary, JsonSerializer.SerializeToUtf8Bytes(record), CancellationToken.None).GetAwaiter().GetResult();
            File.Move(temporary, path, true);
        }
        finally { if (File.Exists(temporary)) SafeFileTree.Delete(temporary); }
    }
    private sealed record Job(string OperationId, string Tag, string Edition, string InstalledTag,
        string AuthorizedSid, int Session, bool Prereleases, DateTimeOffset Expires);
}
