@echo off
rem Opens the one-window Zethora miner (Zethora.ps1 in this folder).
rem Plain text: open Zethora.ps1 in Notepad to read what it does.
start "" powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0Zethora.ps1"
