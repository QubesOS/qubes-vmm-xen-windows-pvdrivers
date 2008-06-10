@echo off
IF NOT EXIST set_ddk_path.bat ECHO >set_ddk_path.bat SET DDK_PATH=C:\WinDDK\6001.17121
CALL set_ddk_path.bat
cmd /C "%DDK_PATH%\bin\setenv.bat %DDK_PATH%\ chk W2K && CD \Projects\win-pvdrivers.hg && build -cZg"
cmd /C "%DDK_PATH%\bin\setenv.bat %DDK_PATH%\ chk WXP && CD \Projects\win-pvdrivers.hg && build -cZg"
cmd /C "%DDK_PATH%\bin\setenv.bat %DDK_PATH%\ chk WNET && CD \Projects\win-pvdrivers.hg && build -cZg"
cmd /C "%DDK_PATH%\bin\setenv.bat %DDK_PATH%\ chk x64 WNET && CD \Projects\win-pvdrivers.hg && build -cZg"
cmd /C "%DDK_PATH%\bin\setenv.bat %DDK_PATH%\ chk WLH && CD \Projects\win-pvdrivers.hg && build -cZg"
cmd /C "%DDK_PATH%\bin\setenv.bat %DDK_PATH%\ chk x64 WLH && CD \Projects\win-pvdrivers.hg && build -cZg"
rem xcopy target\* dist /E /EXCLUDE:exclude.txt /I /D /Y
rem copy doc\*.txt dist
"%ProgramFiles%\NSIS\makensis.exe" installer.nsi