@echo off
rem ============================================================
rem  Start Zethora (testnet) - double-click this file.
rem  This is a plain text script. Open it in Notepad to read
rem  exactly what it does. It only runs the two programs in
rem  this folder. It downloads nothing and changes no settings.
rem ============================================================
title Zethora - status
cd /d "%~dp0"

if not exist "zethora-node.exe" goto missing
if not exist "zethora-miner.exe" goto missing

echo.
echo  ZETHORA TESTNET
echo  ---------------
echo  Step 1 of 3: starting the node (window "Zethora node")...
start "Zethora node" zethora-node.exe --testnet --utxoindex --enable-unsynced-mining

echo  Step 2 of 3: waiting 20 seconds for the node to get ready...
timeout /t 20 /nobreak >nul

echo  Step 3 of 3: starting the miner (window "Zethora miner")...
start "Zethora miner" zethora-miner.exe --testnet

echo.
echo  Both are running. In the "Zethora miner" window:
echo    - your address starts with zethoratest:
echo    - every "Supply check" line should end with BALANCED.
echo      If one does not, run Stop-Zethora and take a screenshot.
echo.
echo  KEEP the file zethora-miner-key-testnet.txt in this folder.
echo  It holds your testnet rewards. Never share it.
echo.
echo  To stop everything: double-click Stop-Zethora.cmd
echo.
timeout /t 40 /nobreak >nul

:balance
echo  [%time%] Your balance:
zethora-miner.exe --testnet balance
echo  (refreshes every 60 seconds - closing this window does not stop mining)
echo.
timeout /t 60 /nobreak >nul
goto balance

:missing
echo.
echo  Can't find zethora-node.exe or zethora-miner.exe.
echo  Unzip the whole download into one folder first
echo  (right-click the zip, Extract All), then double-click
echo  Start-Zethora.cmd inside that folder.
echo.
pause
