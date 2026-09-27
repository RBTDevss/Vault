using System.Windows;
using VaultApp.Services;

namespace VaultApp.Dialogs;

public partial class ChangePasswordDialog : Window
{
    public (string Old, string New)? Result { get; private set; }

    public ChangePasswordDialog()
    {
        InitializeComponent();
        OldBox.Focus();
    }

    private void NewBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        var (label, score) = PasswordStrength.Evaluate(NewBox.Password);
        StrengthLabel.Text = string.IsNullOrEmpty(NewBox.Password) ? "" : $"Strength: {label} ({score}/100)";
        StrengthBar.Value = score;
    }

    private void Ok_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(OldBox.Password) || string.IsNullOrEmpty(NewBox.Password))
        {
            System.Windows.MessageBox.Show(this, "Fill in the old and new passwords.", "Warning",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        if (NewBox.Password != RepeatBox.Password)
        {
            System.Windows.MessageBox.Show(this, "The two new passwords do not match.", "Error",
                MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }
        var (label, score) = PasswordStrength.Evaluate(NewBox.Password);
        if (score < 30)
        {
            var r = System.Windows.MessageBox.Show(this, $"Strength: {label}. Proceed anyway?",
                "Weak password", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (r != MessageBoxResult.Yes) return;
        }
        Result = (OldBox.Password, NewBox.Password);
        DialogResult = true;
        Close();
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        Result = null;
        DialogResult = false;
        Close();
    }
}
