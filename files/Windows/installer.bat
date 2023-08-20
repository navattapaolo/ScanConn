@echo off
setlocal

REM Directory
set "destination=%Path%"

REM Current script name (assuming script extension is .bat)
for %%F in ("%~f0") do set "script_name=%%~nxF"

REM Copy files to the destination directory
echo Copying files to %destination%...
for %%I in (*) do (
    if "%%~nI" neq "%script_name%" (
        xcopy "%%~fI" "%destination%" /S /Y
    )
)