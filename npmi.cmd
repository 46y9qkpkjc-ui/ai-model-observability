@echo off
rem npmi — one-command trigger (cmd.exe shim). Usage: npmi [install]
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0npmi.ps1" %*
