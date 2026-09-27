using System.Collections.ObjectModel;
using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Threading;
using VaultApp.Dialogs;
using VaultApp.Models;
using VaultApp.Services;
using WinForms = System.Windows.Forms;

namespace VaultApp;

public partial class MainWindow : Window
{
    private const int AutolockSeconds = 10 * 60;

    private readonly VaultBridgeClient _bridge = new();
    private readonly ObservableCollection<VaultEntry> _entries = new();
    private List<string> _allGroups = new();
    private string _groupFilter = "";       // "" = all, "__EMPTY__" = no group
    private string _searchText = "";
    private string _sortMode = "Name A→Z";
    private string _vaultPath = "";
    private string _lastGroup = "";
    private bool _unlocked;
    private bool _showPassword;

    private int _busy;
    private readonly object _busyLock = new();
    private DateTime _lastActivity = DateTime.UtcNow;
    private readonly DispatcherTimer _autolockTimer = new();
    private readonly DispatcherTimer _searchTimer = new();
    private bool _refreshing;

    public MainWindow()
    {
        InitializeComponent();
        FilesGrid.ItemsSource = _entries;
        SearchBox.Text = "";
        _autolockTimer.Interval = TimeSpan.FromSeconds(1);
        _autolockTimer.Tick += Autolock_Tick;
        _autolockTimer.Start();
        _searchTimer.Interval = TimeSpan.FromMilliseconds(300);
        _searchTimer.Tick += (_, _) => { _searchTimer.Stop(); _ = RefreshAsync(); };
        Loaded += MainWindow_Loaded;
        Closing += MainWindow_Closing;
    }

    // ================= init =================
    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        LoginStatus.Text = "Starting backend…";
        try
        {
            await Task.Run(() => _bridge.EnsureStarted());
            var kdf = _bridge.HasArgon2 ? "Argon2id (128 MiB)" : "scrypt (N=131072, r=8, p=1)";
            KdfInfoLabel.Text = $"KDF: {kdf}  •  {_bridge.BackendInfo}  •  100% offline";
            LoginStatus.Text = "";
        }
        catch (Exception ex)
        {
            LoginStatus.Text = FriendlyError(ex);
        }
        Touch();
    }

    private void MainWindow_Closing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        try { _autolockTimer.Stop(); } catch { }
        try
        {
            // shut the bridge down without blocking the UI for more than 2 s
            Task.Run(async () => { try { await _bridge.ShutdownAsync(); } catch { } })
                .Wait(TimeSpan.FromSeconds(2));
        }
        catch { }
        _bridge.Dispose();
    }

    // ================= helpers =================
    private bool IsBusy
    {
        get { lock (_busyLock) return _busy > 0; }
    }

    private void SetBusy(bool busy)
    {
        lock (_busyLock) _busy = Math.Max(0, _busy + (busy ? 1 : -1));
        Dispatcher.Invoke(() =>
        {
            if (!busy) MainProgress.Value = 0;
            Cursor = IsBusy ? System.Windows.Input.Cursors.Wait : System.Windows.Input.Cursors.Arrow;
        });
    }

    private void Touch() => _lastActivity = DateTime.UtcNow;

    private void SetStatus(string msg) => StatusLabel.Text = msg;

    private static string FriendlyError(Exception ex)
    {
        if (ex is VaultException ve) return ve.Message;
        return "Unexpected error. See log. No sensitive data shown.";
    }

    private void ShowError(Exception ex, string title = "Error")
    {
        System.Windows.MessageBox.Show(this, FriendlyError(ex), title, System.Windows.MessageBoxButton.OK,
            title == "Error" ? System.Windows.MessageBoxImage.Error : System.Windows.MessageBoxImage.Warning);
    }

    private IProgress<(long Done, long Total)> MakeProgress(string label)
    {
        return new Progress<(long Done, long Total)>(t =>
        {
            double pct = t.Total <= 0 ? 0 : Math.Clamp((double)t.Done / t.Total, 0, 1);
            MainProgress.Value = pct * 1000;
            SetStatus($"{label}… {pct:P0}");
        });
    }

    // ================= login =================
    private void BrowseVault_Click(object sender, RoutedEventArgs e)
    {
        using var dlg = new WinForms.FolderBrowserDialog
        {
            Description = "Pick / create vault folder",
            UseDescriptionForTitle = true,
            ShowNewFolderButton = true,
        };
        if (!string.IsNullOrWhiteSpace(VaultPathBox.Text) && Directory.Exists(VaultPathBox.Text))
            dlg.SelectedPath = VaultPathBox.Text;
        if (dlg.ShowDialog() == WinForms.DialogResult.OK)
        {
            VaultPathBox.Text = dlg.SelectedPath;
            Touch();
        }
    }

    private void PasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        if (_showPassword) return;
        UpdateStrength(PasswordBox.Password);
    }

    private void PasswordVisibleBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (_showPassword)
            UpdateStrength(PasswordVisibleBox.Text);
    }

    private void UpdateStrength(string pw)
    {
        var (label, score) = PasswordStrength.Evaluate(pw);
        StrengthLabel.Text = string.IsNullOrEmpty(pw) ? "" : $"{label} ({score}/100)";
        StrengthBar.Value = score;
        Touch();
    }

    private void ShowPasswordButton_Click(object sender, RoutedEventArgs e)
    {
        _showPassword = !_showPassword;
        if (_showPassword)
        {
            PasswordVisibleBox.Text = PasswordBox.Password;
            PasswordBox.Visibility = Visibility.Collapsed;
            PasswordVisibleBox.Visibility = Visibility.Visible;
            ShowPasswordButton.Content = "Hide";
            UpdateStrength(PasswordVisibleBox.Text);
            PasswordVisibleBox.Focus();
        }
        else
        {
            PasswordBox.Password = PasswordVisibleBox.Text;
            PasswordVisibleBox.Visibility = Visibility.Collapsed;
            PasswordBox.Visibility = Visibility.Visible;
            ShowPasswordButton.Content = "Show";
            UpdateStrength(PasswordBox.Password);
            PasswordBox.Focus();
        }
    }

    private string CurrentPassword() =>
        _showPassword ? PasswordVisibleBox.Text : PasswordBox.Password;

    private void ClearPassword()
    {
        try
        {
            PasswordBox.Password = "";
            PasswordVisibleBox.Text = "";
            StrengthBar.Value = 0;
            StrengthLabel.Text = "";
        }
        catch { }
        GC.Collect();
    }

    private void PasswordBox_KeyDown(object sender, System.Windows.Input.KeyEventArgs e)
    {
        if (e.Key == Key.Enter) OpenVault_Click(sender, e);
    }

    private async void OpenVault_Click(object sender, RoutedEventArgs e)
    {
        var dir = VaultPathBox.Text.Trim().Trim('"', '\'');
        var pw = CurrentPassword();
        if (string.IsNullOrWhiteSpace(dir))
        {
            System.Windows.MessageBox.Show(this, "Select the vault folder.", "Warning",
                System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Warning);
            return;
        }
        if (string.IsNullOrEmpty(pw))
        {
            System.Windows.MessageBox.Show(this, "Enter the password.", "Warning",
                System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Warning);
            return;
        }
        SetBusy(true);
        LoginStatus.Text = "Unlocking (memory-hard KDF, a few seconds)…";
        try
        {
            var data = await _bridge.SendAsync("unlock",
                new { vault_path = dir, password = pw });
            pw = "";
            _vaultPath = data.TryGetProperty("vault_path", out var vp)
                ? vp.GetString() ?? dir : dir;
            _unlocked = true;
            _groupFilter = "";
            _searchText = "";
            SearchBox.Text = "";
            ShowMain();
            await RefreshAsync();
            SetStatus($"Vault unlocked — {_entries.Count} files.  (double-click to extract)");
        }
        catch (Exception ex)
        {
            LoginStatus.Text = FriendlyError(ex);
        }
        finally
        {
            ClearPassword();
            SetBusy(false);
            Touch();
        }
    }

    private async void CreateVault_Click(object sender, RoutedEventArgs e)
    {
        var dir = VaultPathBox.Text.Trim().Trim('"', '\'');
        var pw = CurrentPassword();
        if (string.IsNullOrWhiteSpace(dir))
        {
            System.Windows.MessageBox.Show(this, "Select the vault folder.", "Warning",
                System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Warning);
            return;
        }
        if (string.IsNullOrEmpty(pw))
        {
            System.Windows.MessageBox.Show(this, "Enter the password.", "Warning",
                System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Warning);
            return;
        }
        var (label, score) = PasswordStrength.Evaluate(pw);
        if (score < 30)
        {
            var r = System.Windows.MessageBox.Show(this,
                $"The password is '{label}'. Create the vault anyway?\nA 12+ character passphrase is recommended.",
                "Weak password", System.Windows.MessageBoxButton.YesNo, System.Windows.MessageBoxImage.Warning);
            if (r != System.Windows.MessageBoxResult.Yes) return;
        }
        SetBusy(true);
        LoginStatus.Text = "Creating vault…";
        try
        {
            var data = await _bridge.SendAsync("create",
                new { vault_path = dir, password = pw });
            pw = "";
            _vaultPath = data.TryGetProperty("vault_path", out var vp)
                ? vp.GetString() ?? dir : dir;
            _unlocked = true;
            _groupFilter = "";
            _searchText = "";
            SearchBox.Text = "";
            ShowMain();
            await RefreshAsync();
            SetStatus("New vault created and unlocked.");
        }
        catch (Exception ex)
        {
            LoginStatus.Text = FriendlyError(ex);
        }
        finally
        {
            ClearPassword();
            SetBusy(false);
            Touch();
        }
    }

    private void ShowMain()
    {
        LoginView.Visibility = Visibility.Collapsed;
        MainView.Visibility = Visibility.Visible;
        Title = $"Vault — {_vaultPath}";
        var short_ = _vaultPath.Length > 42 ? "…" + _vaultPath[^41..] : _vaultPath;
        VaultPathLabel.Text = short_;
    }

    private async void LockVault_Click(object sender, RoutedEventArgs e) => await LockAsync(auto: false);

    private async Task LockAsync(bool auto)
    {
        if (IsBusy && !auto)
        {
            System.Windows.MessageBox.Show(this,
                "An encryption/decryption operation is running.\nWait for it to finish before locking.",
                "Operation in progress", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Warning);
            return;
        }
        if (auto && IsBusy) return;
        try { await _bridge.SendAsync("lock", new { }); } catch { }
        _unlocked = false;
        _entries.Clear();
        _allGroups.Clear();
        GroupsPanel.Children.Clear();
        MainView.Visibility = Visibility.Collapsed;
        LoginView.Visibility = Visibility.Visible;
        Title = "Vault — Encrypted Database";
        LoginStatus.Text = auto ? "Vault auto-locked after inactivity." : "";
        if (auto)
        {
            try
            {
                System.Windows.MessageBox.Show(this, "Vault locked after 10 min of inactivity.",
                    "Auto-lock", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Information);
            }
            catch { }
        }
    }

    private void Autolock_Tick(object? sender, EventArgs e)
    {
        if (!_unlocked) return;
        if (IsBusy) { Touch(); return; }
        var rest = AutolockSeconds - (DateTime.UtcNow - _lastActivity).TotalSeconds;
        if (rest <= 0)
        {
            _ = LockAsync(auto: true);
            return;
        }
        AutolockLabel.Text = $"Lock in {(int)rest / 60}:{(int)rest % 60:D2}";
    }

    // ================= list =================
    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        _searchText = SearchBox.Text ?? "";
        Touch();
        _searchTimer.Stop();
        _searchTimer.Start();
    }

    private void SortBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (SortBox.SelectedItem is ComboBoxItem item)
        {
            _sortMode = item.Content?.ToString() ?? "Name A→Z";
            _ = RefreshAsync();
        }
    }

    private static string GetStr(JsonElement el, string name)
    {
        try { return el.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : ""; }
        catch { return ""; }
    }

    private static long GetLong(JsonElement el, string name)
    {
        try
        {
            if (el.TryGetProperty(name, out var v))
            {
                if (v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out var n)) return n;
                if (v.ValueKind == JsonValueKind.String && long.TryParse(v.GetString(), out var m)) return m;
            }
        }
        catch { }
        return 0;
    }

    private async Task RefreshAsync()
    {
        if (!_unlocked) return;
        _refreshing = true;
        try
        {
            var listData = await _bridge.SendAsync("list",
                new { group_filter = _groupFilter, search = _searchText });
            var items = new List<VaultEntry>();
            if (listData.TryGetProperty("files", out var arr) && arr.ValueKind == JsonValueKind.Array)
            {
                foreach (var f in arr.EnumerateArray())
                {
                    items.Add(new VaultEntry
                    {
                        Id = GetStr(f, "id"),
                        Name = GetStr(f, "name"),
                        Group = GetStr(f, "group"),
                        Size = GetLong(f, "size"),
                        Created = GetStr(f, "created"),
                    });
                }
            }
            items = _sortMode switch
            {
                "Recent" => items.OrderByDescending(x => x.Created).ToList(),
                "Largest" => items.OrderByDescending(x => x.Size).ToList(),
                "Group" => items.OrderBy(x => x.GroupDisplay).ThenBy(x => x.Name).ToList(),
                _ => items.OrderBy(x => x.Name, StringComparer.CurrentCultureIgnoreCase).ToList(),
            };

            JsonElement groupsData;
            try { groupsData = await _bridge.SendAsync("groups", new { }); }
            catch { groupsData = default; }
            var groups = new List<string>();
            if (groupsData.ValueKind == JsonValueKind.Object &&
                groupsData.TryGetProperty("groups", out var garr) && garr.ValueKind == JsonValueKind.Array)
            {
                foreach (var g in garr.EnumerateArray())
                    if (g.ValueKind == JsonValueKind.String) groups.Add(g.GetString() ?? "");
            }
            _allGroups = groups;

            _entries.Clear();
            foreach (var it in items) _entries.Add(it);

            RenderGroups(items.Count);
            UpdateStatsAndSelection();
        }
        catch (Exception ex)
        {
            ShowError(ex);
        }
        finally
        {
            _refreshing = false;
            Touch();
        }
    }

    private void RenderGroups(int shownCount)
    {
        GroupsPanel.Children.Clear();
        AddGroupButton("All files", "", null, isActive: _groupFilter is "" or "All");
        AddGroupButton("No group", "__EMPTY__", null, isActive: _groupFilter == "__EMPTY__");
        foreach (var g in _allGroups)
            AddGroupButton(g, g, null, isActive: _groupFilter == g);
    }

    private void AddGroupButton(string label, string key, int? count, bool isActive)
    {
        var b = new System.Windows.Controls.Button
        {
            Content = count.HasValue ? $"{label}  ·  {count}" : label,
            Style = (Style)FindResource("SidebarNavButton"),
            Margin = new Thickness(0, 1, 0, 1),
            Tag = key,
        };
        if (isActive)
        {
            b.Background = new System.Windows.Media.SolidColorBrush(
                System.Windows.Media.Color.FromRgb(0x2E, 0x9B, 0xEE));
            b.Foreground = System.Windows.Media.Brushes.White;
        }
        b.Click += (_, _) =>
        {
            _groupFilter = key;
            Touch();
            _ = RefreshAsync();
        };
        GroupsPanel.Children.Add(b);
    }

    private void UpdateStatsAndSelection()
    {
        long shown = _entries.Sum(x => x.Size);
        StatsLabel.Text = $"{_entries.Count} files shown\n{VaultEntry.FormatSize(shown)}";
        var sel = FilesGrid.SelectedItems.Count;
        SelectionLabel.Text = sel == 0
            ? $"{_entries.Count} files • double-click to extract • Ctrl+click for multi-select"
            : sel == 1 ? "1 file selected" : $"{sel} files selected";
        bool empty = _entries.Count == 0;
        EmptyState.Visibility = empty ? Visibility.Visible : Visibility.Collapsed;
        EmptyStateText.Text = string.IsNullOrEmpty(_searchText) && string.IsNullOrEmpty(_groupFilter)
            ? "Vault is empty.\nPress + File or + Folder to encrypt your first files."
            : "No files found.\nTry changing the search or group.";
    }

    private void FilesGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_refreshing) return;
        Touch();
        UpdateStatsAndSelection();
    }

    private void FilesGrid_DoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (FilesGrid.SelectedItem is VaultEntry)
            Extract_Click(sender, e);
    }

    private List<string> SelectedIds() =>
        FilesGrid.SelectedItems.OfType<VaultEntry>().Select(x => x.Id)
            .Where(id => !string.IsNullOrEmpty(id)).ToList();

    private void SelectAll_Click(object sender, RoutedEventArgs e)
    {
        FilesGrid.SelectAll();
        Touch();
    }

    // ================= import =================
    private async void AddFiles_Click(object sender, RoutedEventArgs e)
    {
        if (!_unlocked) return;
        var dlg = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Select files to encrypt into the vault",
            Multiselect = true,
        };
        if (dlg.ShowDialog(this) != true) return;
        var initial = string.IsNullOrEmpty(_lastGroup)
            ? (_groupFilter is "" or "All" or "__EMPTY__" ? "" : _groupFilter)
            : _lastGroup;
        var gd = new GroupDialog("Group for these files", initial, _allGroups) { Owner = this };
        if (gd.ShowDialog() != true) return;
        var group = gd.Result ?? "";
        var sd = new ShredDialog { Owner = this };
        if (sd.ShowDialog() != true || sd.Result is null) return;
        bool shred = sd.Result.Value;
        _lastGroup = group;

        SetBusy(true);
        try
        {
            var data = await _bridge.SendAsync("add_files",
                new { paths = dlg.FileNames, group, shred },
                MakeProgress($"Encrypting {dlg.FileNames.Length} files"));
            int n = data.TryGetProperty("count", out var c) ? c.GetInt32() : dlg.FileNames.Length;
            await RefreshAsync();
            SetStatus($"Imported {n} files into group '{(string.IsNullOrEmpty(group) ? "-" : group)}'.");
        }
        catch (Exception ex) { ShowError(ex); }
        finally { SetBusy(false); Touch(); }
    }

    private async void AddFolder_Click(object sender, RoutedEventArgs e)
    {
        if (!_unlocked) return;
        using var dlg = new WinForms.FolderBrowserDialog
        {
            Description = "Select folder to encrypt (file group)",
            UseDescriptionForTitle = true,
            ShowNewFolderButton = false,
        };
        if (dlg.ShowDialog() != WinForms.DialogResult.OK) return;
        string initial;
        try { initial = string.IsNullOrEmpty(_lastGroup) ? Path.GetFileName(Path.GetFullPath(dlg.SelectedPath)) : _lastGroup; }
        catch { initial = _lastGroup; }
        var gd = new GroupDialog("Group for this folder", initial ?? "", _allGroups) { Owner = this };
        if (gd.ShowDialog() != true) return;
        var group = gd.Result ?? "";
        var sd = new ShredDialog { Owner = this };
        if (sd.ShowDialog() != true || sd.Result is null) return;
        bool shred = sd.Result.Value;
        _lastGroup = group;

        SetBusy(true);
        try
        {
            var data = await _bridge.SendAsync("add_folder",
                new { folder = dlg.SelectedPath, group, shred },
                MakeProgress("Encrypting folder"));
            int n = data.TryGetProperty("count", out var c) ? c.GetInt32() : 0;
            await RefreshAsync();
            SetStatus($"Imported {n} files from the folder.");
        }
        catch (Exception ex) { ShowError(ex); }
        finally { SetBusy(false); Touch(); }
    }

    // ================= export / delete / groups / password =================
    private async void Extract_Click(object sender, RoutedEventArgs e)
    {
        if (!_unlocked) return;
        var ids = SelectedIds();
        if (ids.Count == 0)
        {
            System.Windows.MessageBox.Show(this, "Select at least one file from the list.", "No selection",
                System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Information);
            return;
        }
        SetBusy(true);
        try
        {
            if (ids.Count == 1)
            {
                var entry = _entries.FirstOrDefault(x => x.Id == ids[0]);
                var save = new Microsoft.Win32.SaveFileDialog
                {
                    Title = "Extract and decrypt as…",
                    FileName = entry?.Name ?? "file",
                };
                if (save.ShowDialog(this) != true) { return; }
                var data = await _bridge.SendAsync("extract_file",
                    new { file_id = ids[0], dest_path = save.FileName },
                    MakeProgress("Decryption"));
                var path = data.TryGetProperty("path", out var p) ? p.GetString() ?? save.FileName : save.FileName;
                System.Windows.MessageBox.Show(this, $"Decrypted and verified file (SHA-256):\n{path}",
                    "Extracted", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Information);
            }
            else
            {
                using var dlg = new WinForms.FolderBrowserDialog
                {
                    Description = $"Destination folder ({ids.Count} files)",
                    UseDescriptionForTitle = true,
                    ShowNewFolderButton = true,
                };
                if (dlg.ShowDialog() != WinForms.DialogResult.OK) return;
                var data = await _bridge.SendAsync("extract_selected",
                    new { ids, dest_dir = dlg.SelectedPath },
                    MakeProgress($"Decrypting {ids.Count} files"));
                int n = data.TryGetProperty("count", out var c) ? c.GetInt32() : ids.Count;
                System.Windows.MessageBox.Show(this, $"{n} files decrypted and verified in:\n{dlg.SelectedPath}",
                    "Extracted", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Information);
            }
        }
        catch (Exception ex) { ShowError(ex); }
        finally { SetBusy(false); Touch(); }
    }

    private async void ExtractAll_Click(object sender, RoutedEventArgs e)
    {
        if (!_unlocked) return;
        using var dlg = new WinForms.FolderBrowserDialog
        {
            Description = "Destination folder (entire vault)",
            UseDescriptionForTitle = true,
            ShowNewFolderButton = true,
        };
        if (dlg.ShowDialog() != WinForms.DialogResult.OK) return;
        SetBusy(true);
        try
        {
            var data = await _bridge.SendAsync("extract_all",
                new { dest_dir = dlg.SelectedPath, group_filter = _groupFilter },
                MakeProgress("Full extraction"));
            int n = data.TryGetProperty("count", out var c) ? c.GetInt32() : 0;
            System.Windows.MessageBox.Show(this, $"{n} files decrypted and verified (SHA-256).",
                "Extracted", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Information);
        }
        catch (Exception ex) { ShowError(ex); }
        finally { SetBusy(false); Touch(); }
    }

    private async void Delete_Click(object sender, RoutedEventArgs e)
    {
        if (!_unlocked) return;
        var ids = SelectedIds();
        if (ids.Count == 0)
        {
            System.Windows.MessageBox.Show(this, "Select at least one file.", "No selection",
                System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Information);
            return;
        }
        var names = _entries.Where(x => ids.Contains(x.Id)).Take(8).Select(x => "- " + x.Name).ToList();
        var preview = string.Join("\n", names) + (ids.Count > 8 ? $"\n…and {ids.Count - 8} more files." : "");
        var cd = new ConfirmDeleteDialog(ids.Count, preview) { Owner = this };
        if (cd.ShowDialog() != true || !cd.Confirmed) return;

        SetBusy(true);
        try
        {
            await _bridge.SendAsync("delete", new { ids }, MakeProgress("Secure deletion (shredding)"));
            await RefreshAsync();
            SetStatus($"Deleted {ids.Count} files with shredding.");
        }
        catch (Exception ex) { ShowError(ex); }
        finally { SetBusy(false); Touch(); }
    }

    private async void MoveGroup_Click(object sender, RoutedEventArgs e)
    {
        if (!_unlocked) return;
        var ids = SelectedIds();
        if (ids.Count == 0)
        {
            System.Windows.MessageBox.Show(this, "Select at least one file.", "No selection",
                System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Information);
            return;
        }
        var gd = new GroupDialog($"Move {ids.Count} files to group", "", _allGroups) { Owner = this };
        if (gd.ShowDialog() != true) return;
        var ng = gd.Result ?? "";
        try
        {
            await _bridge.SendAsync("move_group", new { ids, new_group = ng });
            await RefreshAsync();
            SetStatus($"{ids.Count} files moved to '{(string.IsNullOrEmpty(ng) ? "No group" : ng)}'.");
        }
        catch (Exception ex) { ShowError(ex); }
        finally { Touch(); }
    }

    private async void ChangePassword_Click(object sender, RoutedEventArgs e)
    {
        if (!_unlocked) return;
        if (IsBusy)
        {
            System.Windows.MessageBox.Show(this, "Wait for completion before changing the password.",
                "Operation in progress", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Warning);
            return;
        }
        var dlg = new ChangePasswordDialog { Owner = this };
        if (dlg.ShowDialog() != true || dlg.Result is null) return;
        var (oldPw, newPw) = dlg.Result.Value;
        try
        {
            await _bridge.SendAsync("change_password",
                new { old_password = oldPw, new_password = newPw });
            Touch();
            SetStatus("Password changed (master key re-wrapped).");
            System.Windows.MessageBox.Show(this, "Password changed. Your data was NOT re-encrypted\n(only the master key was re-wrapped).",
                "OK", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Information);
        }
        catch (Exception ex) { ShowError(ex); }
    }
}
