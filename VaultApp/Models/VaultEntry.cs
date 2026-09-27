namespace VaultApp.Models;

public sealed class VaultEntry
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string Group { get; set; } = "";
    public long Size { get; set; }
    public string Created { get; set; } = "";

    public string GroupDisplay => string.IsNullOrWhiteSpace(Group) ? "No group" : Group;
    public string SizeDisplay => FormatSize(Size);
    public string DateDisplay => ((Created ?? "").Length >= 16)
        ? (Created ?? "").Replace("T", " ").Substring(0, 16)
        : (Created ?? "");

    public static string FormatSize(long n)
    {
        if (n < 0) n = 0;
        double f = n;
        string[] units = { "B", "KB", "MB", "GB", "TB" };
        foreach (var u in units)
        {
            if (f < 1024 || u == "TB")
                return u == "B" ? $"{(int)f} {u}" : $"{f:F1} {u}";
            f /= 1024;
        }
        return $"{f:F1} TB";
    }
}
