@echo off
rem ============================================================
rem  X M I N E R Z - The Zethora CPU Miner
rem  Double-click this file to start mining Zethora testnet.
rem
rem  This is a plain text script. Open it in Notepad to read
rem  exactly what it does. It only opens XminerZ.ps1 in this
rem  folder, which runs the programs that are already here.
rem  It downloads nothing and changes no settings.
rem
rem  Testnet only: coins have no value and no token exists.
rem ============================================================
title XminerZ - Zethora CPU Miner
cd /d "%~dp0"

if not exist "XminerZ.ps1" goto missing
if not exist "zethora-node.exe" goto missing
if not exist "zethora-miner.exe" goto missing

rem -NoProfile       : run with a clean PowerShell, not your own settings
rem -ExecutionPolicy Bypass : allow this unsigned script to run
rem -NoLogo          : no PowerShell banner above the XminerZ one
rem -File            : run XminerZ.ps1 from THIS folder, whatever the current one is
powershell -NoProfile -NoLogo -ExecutionPolicy Bypass -File "%~dp0XminerZ.ps1"
set "XMZ_EXIT=%ERRORLEVEL%"

echo.
echo  XminerZ has stopped. Your key file and your coins are kept.
if not "%XMZ_EXIT%"=="0" echo  (exit code %XMZ_EXIT% - the message above says why)
echo.
pause
exit /b %XMZ_EXIT%

:missing
echo.
echo  Can't find XminerZ.ps1, zethora-node.exe or zethora-miner.exe.
echo  Unzip the WHOLE download into one folder first
echo  (right-click the zip, Extract All), then double-click
echo  XminerZ.bat inside that folder.
echo.
pause
exit /b 1
