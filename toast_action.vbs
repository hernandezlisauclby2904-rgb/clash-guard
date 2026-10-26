' Clash Guard Toast protocol handler.
' Accepts only a small allow-list; never forwards arbitrary URI text to PowerShell.
Option Explicit
Dim fso, shell, baseDir, scriptPath, uri, action, q, cmd
Set fso = CreateObject("Scripting.FileSystemObject")
Set shell = CreateObject("WScript.Shell")
If WScript.Arguments.Count < 1 Then WScript.Quit 2
uri = LCase(Trim(CStr(WScript.Arguments(0))))
If Left(uri, 11) <> "clashguard:" Then WScript.Quit 3
action = Mid(uri, 12)
If InStr(action, "?") > 0 Then action = Left(action, InStr(action, "?") - 1)
If InStr(action, "#") > 0 Then action = Left(action, InStr(action, "#") - 1)
Select Case action
  Case "fix", "openip", "checkleaks", "start", "protect"
    ' allowed action
  Case Else
    WScript.Quit 4
End Select
baseDir = fso.GetParentFolderName(WScript.ScriptFullName)
scriptPath = fso.BuildPath(baseDir, "clash_guard.ps1")
If Not fso.FileExists(scriptPath) Then WScript.Quit 5
q = Chr(34)
scriptPath = Replace(scriptPath, q, q & q)
cmd = q & shell.ExpandEnvironmentStrings("%WINDIR%\System32\WindowsPowerShell\v1.0\powershell.exe") & q & _
      " -NoProfile -WindowStyle Hidden -NonInteractive -ExecutionPolicy Bypass -File " & q & scriptPath & q & _
      " -ToastAction " & action
shell.Run cmd, 0, False
