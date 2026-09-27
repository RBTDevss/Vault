namespace VaultApp.Services;

public static class PasswordStrength
{
    private static readonly string[] Banal = { "password", "123456", "qwerty", "vault", "admin", "hello" };

    public static (string Label, int Score) Evaluate(string? pw)
    {
        if (string.IsNullOrEmpty(pw)) return ("Empty", 0);
        int length = pw.Length;
        int classes = 0;
        if (pw.Any(char.IsLower)) classes++;
        if (pw.Any(char.IsUpper)) classes++;
        if (pw.Any(char.IsDigit)) classes++;
        if (pw.Any(c => !char.IsLetterOrDigit(c))) classes++;

        int penalty = 0;
        var lowered = pw.ToLowerInvariant();
        foreach (var b in Banal)
            if (lowered.Contains(b)) penalty += 25;

        int score = Math.Min(100, length * 5 + (classes - 1) * 12 - penalty);
        score = Math.Max(0, score);

        string label = score < 30 ? "Weak" : score < 55 ? "Fair" : score < 80 ? "Strong" : "Very strong";
        if (length < 12) label += " — use 12+ characters";
        return (label, score);
    }
}
