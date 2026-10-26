' 静默启动器：通过 wscript 调用任意命令，不显示任何窗口
' 用法: wscript run_hidden.vbs "command arg1 arg2"
On Error Resume Next
Set args = WScript.Arguments
If args.Count = 0 Then WScript.Quit 1
cmdLine = args.Item(0)
For i = 1 To args.Count - 1
    cmdLine = cmdLine & " " & Chr(34) & args.Item(i) & Chr(34)
Next
Set WshShell = CreateObject("WScript.Shell")
WshShell.Run cmdLine, 0, False
