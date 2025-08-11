@echo off
SET script=%~dp0\99PowershellSwissArmyKnife.ps1
NET SESSION >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    PowerShell -Command "Start-Process -FilePath 'cmd.exe' -ArgumentList '/c \"%~f0\"' -Verb RunAs"
    EXIT /B
)
PowerShell -NoProfile -ExecutionPolicy Bypass -File "%script%"
pause
