// See https://aka.ms/new-console-template for more information

using System.Diagnostics;
using AppContainerWrapper;

Console.WriteLine("Hello, World!");

var creator = new AppContainerCreator();
var processStartInfo = new ProcessStartInfo(@"C:\\Windows\\System32\\notepad.exe");
//var processStartInfo = new ProcessStartInfo(@"C:\\Program Files\\Notepad++\\notepad++.exe");

creator.SandboxProcess(processStartInfo.FileName);
