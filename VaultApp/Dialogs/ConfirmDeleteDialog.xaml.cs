using System.Windows;

namespace VaultApp.Dialogs;

public partial class ConfirmDeleteDialog : Window
{
    public bool Confirmed { get; private set; }

    public ConfirmDeleteDialog(int count, string preview)
    {
        InitializeComponent();
        TitleText.Text = $"Delete {count} files?";
        PreviewText.Text = preview;
    }

    private void Ok_Click(object sender, RoutedEventArgs e)
    {
        Confirmed = true; DialogResult = true; Close();
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        Confirmed = false; DialogResult = false; Close();
    }
}
