using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;

namespace VaultApp.Services;

/// <summary>
/// JSON-line client for vault_bridge.py (unchanged Python core).
/// The bridge stays alive, holds the master key in RAM and answers by id.
/// Progress arrives as interleaved {type:progress} events.
/// </summary>
public sealed class VaultBridgeClient : IDisposable
{
    private Process? _proc;
    private StreamWriter? _writer;
    private readonly object _writeLock = new();
    private readonly Dictionary<long, PendingCall> _pending = new();
    private readonly object _pendingLock = new();
    private long _nextId = 1;
    private Thread? _readerThread;
    private volatile bool _running;
    private string _stderrLog = "";

    private sealed class PendingCall
    {
        public TaskCompletionSource<JsonElement> Tcs { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public IProgress<(long Done, long Total)>? Progress { get; set; }
    }

    public bool IsRunning => _proc is { HasExited: false } && _running;

    public string BackendInfo { get; private set; } = "";
    public bool HasArgon2 { get; private set; }

    public void EnsureStarted()
    {
        if (IsRunning) return;
        DisposeProcess();

        var bridge = FindBridge(out var bridgeDir);
        var (pythonExe, pythonArgs) = FindPython();
        var psi = new ProcessStartInfo
        {
            FileName = pythonExe,
            Arguments = pythonArgs + $"-u \"{bridge}\"",
            WorkingDirectory = bridgeDir,
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardInputEncoding = new UTF8Encoding(false),
            StandardOutputEncoding = new UTF8Encoding(false),
        };
        // Shield Python from user env vars that could break stdio
        psi.Environment["PYTHONIOENCODING"] = "utf-8";
        psi.Environment["PYTHONUTF8"] = "1";

        _proc = new Process { StartInfo = psi, EnableRaisingEvents = true };
        if (!_proc.Start())
            throw new InvalidOperationException("Cannot start the Python backend.");
        _writer = _proc.StandardInput;
        _running = true;

        _proc.ErrorDataReceived += (_, e) =>
        {
            if (e.Data != null)
            {
                lock (_pendingLock)
                {
                    _stderrLog += e.Data + "\n";
                    if (_stderrLog.Length > 8000) _stderrLog = _stderrLog[^8000..];
                }
            }
        };
        _proc.BeginErrorReadLine();

        _readerThread = new Thread(ReaderLoop) { IsBackground = true, Name = "vault-bridge-reader" };
        _readerThread.Start();

        // verification ping (throws when Python/deps are missing)
        try
        {
            var data = SendAsync("ping", new { }).GetAwaiter().GetResult();
            BackendInfo = data.TryGetProperty("backend", out var b) ? b.GetString() ?? "" : "";
            HasArgon2 = data.TryGetProperty("has_argon2", out var a) && a.GetBoolean();
        }
        catch (Exception ex)
        {
            var tail = "";
            lock (_pendingLock) tail = _stderrLog;
            DisposeProcess();
            throw new InvalidOperationException(
                "Python backend did not start.\n" +
                "You need Python with: pip install pycryptodomex (argon2-cffi recommended).\n" +
                $"Detail: {ex.Message}\n{tail}");
        }
    }

    private static string FindBridge(out string dir)
    {
        var candidates = new List<string>();
        var baseDir = AppContext.BaseDirectory;
        candidates.Add(Path.Combine(baseDir, "vault_bridge.py"));
        // dev layout: VaultApp/ as a subfolder of vault/
        var parent = Directory.GetParent(baseDir);
        for (int i = 0; i < 5 && parent != null; i++)
        {
            candidates.Add(Path.Combine(parent.FullName, "vault_bridge.py"));
            candidates.Add(Path.Combine(parent.FullName, "vault", "vault_bridge.py"));
            parent = parent.Parent;
        }
        candidates.Add(Path.Combine(Directory.GetCurrentDirectory(), "vault_bridge.py"));
        candidates.Add(Path.Combine(Directory.GetCurrentDirectory(), "..", "vault_bridge.py"));
        foreach (var c in candidates)
        {
            try
            {
                var full = Path.GetFullPath(c);
                if (File.Exists(full))
                {
                    dir = Path.GetDirectoryName(full)!;
                    if (!File.Exists(Path.Combine(dir, "secure_vault.py")))
                    {
                        foreach (var c2 in candidates)
                        {
                            var d2 = Path.GetDirectoryName(Path.GetFullPath(c2));
                            if (d2 != null && File.Exists(Path.Combine(d2, "secure_vault.py")))
                            {
                                CopyIfNewer(Path.Combine(d2, "secure_vault.py"), Path.Combine(dir, "secure_vault.py"));
                                break;
                            }
                        }
                    }
                    return full;
                }
            }
            catch { }
        }
        throw new FileNotFoundException(
            "vault_bridge.py not found. Copy secure_vault.py + vault_bridge.py next to the executable.");
    }

    private static void CopyIfNewer(string src, string dst)
    {
        try
        {
            if (!File.Exists(dst) || File.GetLastWriteTimeUtc(src) > File.GetLastWriteTimeUtc(dst))
                File.Copy(src, dst, true);
        }
        catch { }
    }

    private static (string Exe, string ArgsPrefix) FindPython()
    {
        // 1) python on PATH, 2) py launcher
        foreach (var cmd in new[] { "python", "python3" })
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = cmd,
                    Arguments = "--version",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                };
                using var p = Process.Start(psi);
                if (p == null) continue;
                p.WaitForExit(8000);
                if (p.ExitCode == 0) return (cmd, "");
            }
            catch { }
        }
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "py",
                Arguments = "-3 --version",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            using var p = Process.Start(psi);
            if (p != null)
            {
                p.WaitForExit(8000);
                if (p.ExitCode == 0) return ("py", "-3 ");
            }
        }
        catch { }
        return ("python", ""); // let it fail with a clear message in EnsureStarted
    }

    public Task<JsonElement> SendAsync(string cmd, object? @params,
        IProgress<(long Done, long Total)>? progress = null,
        CancellationToken ct = default)
    {
        EnsureStarted();
        long id;
        PendingCall call;
        lock (_pendingLock)
        {
            id = _nextId++;
            call = new PendingCall { Progress = progress };
            _pending[id] = call;
        }
        if (ct.CanBeCanceled)
            ct.Register(() => call.Tcs.TrySetCanceled(ct));

        var req = new Dictionary<string, object?> { ["id"] = id, ["cmd"] = cmd, ["params"] = @params ?? new { } };
        var line = JsonSerializer.Serialize(req);
        lock (_writeLock)
        {
            try
            {
                _writer!.WriteLine(line);
                _writer.Flush();
            }
            catch (Exception ex)
            {
                lock (_pendingLock) _pending.Remove(id);
                throw new InvalidOperationException("Backend unreachable (stdin closed). Restart the app. " + ex.Message);
            }
        }
        return call.Tcs.Task;
    }

    private void ReaderLoop()
    {
        try
        {
            var reader = _proc!.StandardOutput;
            string? line;
            while (_running && (line = reader.ReadLine()) != null)
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                JsonDocument doc;
                try { doc = JsonDocument.Parse(line); }
                catch { continue; }
                using (doc)
                {
                    var root = doc.RootElement;
                    if (!root.TryGetProperty("id", out var idProp) || idProp.ValueKind != JsonValueKind.Number)
                        continue;
                    long id = idProp.GetInt64();
                    string type = root.TryGetProperty("type", out var t) ? t.GetString() ?? "" : "";
                    PendingCall? call;
                    lock (_pendingLock) _pending.TryGetValue(id, out call);
                    if (call == null) continue;

                    if (type == "progress")
                    {
                        long done = root.TryGetProperty("done", out var d) ? d.GetInt64() : 0;
                        long total = root.TryGetProperty("total", out var tt) ? tt.GetInt64() : 1;
                        try { call.Progress?.Report((done, total)); } catch { }
                    }
                    else if (type == "result")
                    {
                        bool ok = !root.TryGetProperty("ok", out var o) || o.GetBoolean();
                        if (ok)
                        {
                            var data = root.TryGetProperty("data", out var dd)
                                ? dd.Clone() : JsonDocument.Parse("{}").RootElement;
                            lock (_pendingLock) _pending.Remove(id);
                            call.Tcs.TrySetResult(data);
                        }
                        else
                        {
                            string err = root.TryGetProperty("error", out var e) ? e.GetString() ?? "Error" : "Error";
                            lock (_pendingLock) _pending.Remove(id);
                            call.Tcs.TrySetException(new VaultException(err));
                        }
                    }
                    else if (type == "error")
                    {
                        string err = root.TryGetProperty("error", out var e) ? e.GetString() ?? "Error" : "Error";
                        lock (_pendingLock) _pending.Remove(id);
                        call.Tcs.TrySetException(new VaultException(err));
                    }
                }
            }
        }
        catch { }
        finally
        {
            // bridge died: fail every pending call
            List<PendingCall> left;
            lock (_pendingLock)
            {
                left = _pending.Values.ToList();
                _pending.Clear();
            }
            foreach (var c in left)
                c.Tcs.TrySetException(new InvalidOperationException("The Python backend closed unexpectedly."));
            _running = false;
        }
    }

    public async Task ShutdownAsync()
    {
        if (!IsRunning) return;
        try
        {
            using var cts = new CancellationTokenSource(3000);
            await SendAsync("shutdown", new { }, null, cts.Token);
        }
        catch { }
        DisposeProcess();
    }

    private void DisposeProcess()
    {
        _running = false;
        try { _writer?.Close(); } catch { }
        try
        {
            if (_proc is { HasExited: false })
            {
                _proc.Kill(entireProcessTree: true);
            }
        }
        catch { }
        try { _proc?.Dispose(); } catch { }
        _proc = null;
        _writer = null;
    }

    public void Dispose() => DisposeProcess();
}

public sealed class VaultException : Exception
{
    public VaultException(string message) : base(message) { }
}
