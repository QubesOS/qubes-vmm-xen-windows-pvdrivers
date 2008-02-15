@ECHO OFF

ver | find "Version 5.2." > nul
if %ERRORLEVEL% == 0 goto ver_2003

ver | find "Version 5.1." > nul
if %ERRORLEVEL% == 0 goto ver_xp

echo No automatic install available or machine not supported.
goto exit

:ver_2003
echo Windows 2003 Detected... Installing...
shutdownmon -i
cd winnet
dpinst.exe /LM
echo Done
goto exit

:ver_xp
echo Windows XP Detected... Installing...
shutdownmon -i
cd winnet
dpinst.exe /LM
echo Done
goto exit

pause
:exit