@echo off
setlocal

REM Get the directory where the current script is located
set "script_dir=%~dp0"

REM Remove trailing backslash from the directory path if present
if "%script_dir:~-1%"=="\" set "script_dir=%script_dir:~0,-1%"

REM Display the directory being added to the Path 
echo Adding %script_dir% to the system PATH...

REM Add the directory to the system PATH
setx PATH "%PATH%;%script_dir%"

REM Notify the user that the installation is completed
echo Installation completed

REM End the script and revert any local environment changes
endlocal
