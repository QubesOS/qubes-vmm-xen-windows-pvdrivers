@echo off
cmd /C "C:\WinDDK\6001.17121\bin\setenv.bat C:\WinDDK\6001.17121\ chk x64 WNET && CD \Projects\win-pvdrivers.hg && build -cZg"
cmd /C "C:\WinDDK\6001.17121\bin\setenv.bat C:\WinDDK\6001.17121\ chk WNET && CD \Projects\win-pvdrivers.hg && build -cZg"
cmd /C "C:\WinDDK\6001.17121\bin\setenv.bat C:\WinDDK\6001.17121\ chk WXP && CD \Projects\win-pvdrivers.hg && build -cZg"
xcopy target\* dist /E /EXCLUDE:exclude.txt /I /D /Y
copy doc\*.txt dist
