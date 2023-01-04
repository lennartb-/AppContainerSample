using System.Diagnostics;
using System.IO;
using AppContainerWrapper;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using Serilog;

namespace AppContainerSampleApp;

/// <summary>
///     Viewmodel for <see cref="MainWindow" />.
/// </summary>
public partial class MainWindowVm : ObservableObject
{
    private readonly ILogger logger;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(RunCommand))]
    private string executable = @"C:\\Windows\\System32\\notepad.exe";

    /// <summary>
    ///     Initializes a new instance of the <see cref="MainWindowVm" /> class.
    /// </summary>
    /// <param name="logger">An <see cref="ILogger" /> instance.</param>
    public MainWindowVm(ILogger logger)
    {
        this.logger = logger;
        SelectAppCommand = new RelayCommand(SelectApp);
        RunCommand = new RelayCommand(Run, CanRun);
    }

    /// <summary>
    ///     Gets the command that is executed when the app container should start.
    /// </summary>
    public IRelayCommand RunCommand { get; }

    /// <summary>
    ///     Gets the command that is executed when an application to sandbox should be selected.
    /// </summary>
    public IRelayCommand SelectAppCommand { get; }

    private bool CanRun()
    {
        return File.Exists(Executable);
    }

    private void Run()
    {
        var creator = new AppContainerCreator(logger);
        var processStartInfo = new ProcessStartInfo(Executable);

        creator.SandboxProcess(processStartInfo.FileName);
    }

    private void SelectApp()
    {
        var dialog = new OpenFileDialog { Filter = "Executable files (.exe)|*.exe" };

        var result = dialog.ShowDialog();

        if (result == true)
        {
            Executable = dialog.FileName;
        }
    }
}