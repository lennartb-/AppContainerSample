using System.Diagnostics;
using System.IO;
using AppContainerWrapper;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using Serilog.Core;

namespace AppContainerSampleApp;

public partial class MainWindowVm : ObservableObject
{
    private readonly Logger logger;

    [ObservableProperty] [NotifyCanExecuteChangedFor(nameof(RunCommand))]
    private string executable = @"C:\\Windows\\System32\\notepad.exe";

    public MainWindowVm(Logger logger)
    {
        this.logger = logger;
        SelectAppCommand = new RelayCommand(SelectApp);
        RunCommand = new RelayCommand(Run, CanRun);
    }

    public IRelayCommand SelectAppCommand { get; set; }
    public IRelayCommand RunCommand { get; set; }

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
        var dialog = new OpenFileDialog
        {
            Filter = "Executable files (.exe)|*.exe"
        };

        var result = dialog.ShowDialog();

        if (result == true)
        {
            Executable = dialog.FileName;
        }
    }
}