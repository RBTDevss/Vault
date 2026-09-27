using System.Windows;

namespace VaultApp.Dialogs;

public partial class ShredDialog : Window
{
    /// <summary>True=destroy, False=keep, Null=cancel.</summary>
    public bool? Result { get; private set; }

    public ShredDialog()
    {
        InitializeComponent();
    }

    private void Yes_Click(object sender, RoutedEventArgs e)
    {
        Result = true; DialogResult = true; Close();
    }

    private void No_Click(object sender, RoutedEventArgs e)
    {
        Result = false; DialogResult = true; Close();
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        Result = null; DialogResult = false; Close();
    }
}
