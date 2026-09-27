using System.Windows;

namespace VaultApp.Dialogs;

public partial class GroupDialog : Window
{
    public string? Result { get; private set; }

    public GroupDialog(string title, string initial, IEnumerable<string> groups)
    {
        InitializeComponent();
        TitleText.Text = title;
        GroupBox.Text = initial ?? "";
        foreach (var g in groups.Take(30))
            ExistingList.Items.Add(g);
        GroupBox.Focus();
        GroupBox.SelectAll();
    }

    private void ExistingList_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (ExistingList.SelectedItem is string s)
            GroupBox.Text = s;
    }

    private void Ok_Click(object sender, RoutedEventArgs e)
    {
        Result = GroupBox.Text.Trim();
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
