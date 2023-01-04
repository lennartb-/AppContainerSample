using Serilog;

namespace AppContainerSampleApp;

/// <summary>
///     Interaction logic for MainWindow.xaml.
/// </summary>
public partial class MainWindow
{
    /// <summary>
    /// Initializes a new instance of the <see cref="MainWindow"/> class.
    /// </summary>
    public MainWindow()
    {
        InitializeComponent();
        var logger = new LoggerConfiguration()
            .WriteTo.RichTextBox(RichTextBox)
            .CreateLogger();
        DataContext = new MainWindowVm(logger);
    }
}