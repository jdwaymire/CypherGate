@echo off
REM Launch the CypherGate server. Ctrl-C in this window stops everything.
REM
REM Strictly portable: the interpreter and the SSH client both travel with this
REM folder. Nothing on the machine is used, and nothing is installed.
setlocal
cd /d "%~dp0"

set PY=%~dp0python\python.exe
if not exist "%PY%" (
  echo.
  echo Missing python\python.exe - the bundled interpreter is required.
  echo Restore the python\ folder, or re-download the Windows embeddable
  echo package from https://www.python.org/downloads/windows/
  echo.
  pause
  exit /b 1
)

if not exist "%~dp0ssh\ssh.exe" (
  echo.
  echo Missing ssh\ssh.exe - the bundled OpenSSH client is required.
  echo Restore the ssh\ folder, or re-download OpenSSH-Win64.zip from
  echo https://github.com/PowerShell/Win32-OpenSSH/releases
  echo.
  pause
  exit /b 1
)

REM Keep the URL printed here from drifting away from the one the server
REM actually binds, which honours CYPHERGATE_PORT.
if "%CYPHERGATE_PORT%"=="" set CYPHERGATE_PORT=8765

echo Starting CypherGate on http://127.0.0.1:%CYPHERGATE_PORT%
echo Your browser will open there by itself; unlock it with the master password.
echo.

REM --open-browser is opt-in on purpose: the server opens the page once its
REM socket is bound, so there is no race, and an autostart-at-login run that
REM omits the flag stays silent.
"%PY%" server.py --open-browser
pause
