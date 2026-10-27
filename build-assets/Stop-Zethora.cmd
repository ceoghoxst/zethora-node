@echo off
rem Stop Zethora - closes the miner first, then the node.
rem Plain text script: open in Notepad to read it.
title Zethora - stop
echo Stopping the miner...
taskkill /f /im zethora-miner.exe >nul 2>&1
timeout /t 3 /nobreak >nul
echo Stopping the node...
taskkill /f /im zethora-node.exe >nul 2>&1
echo Done. Your key file and rewards are kept.
pause
