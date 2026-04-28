' Jigsaw silent GUI launcher - avoids a blinking CMD window when using pythonw.exe
' Author: Kennedy Aikohi
Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
base = fso.GetParentFolderName(WScript.ScriptFullName)
cmd = "pythonw.exe """ & base & "\jigsaw.py"""
shell.Run cmd, 0, False
