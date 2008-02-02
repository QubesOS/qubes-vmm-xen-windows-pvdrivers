@echo off
cmd /C "C:\WinDDK\6000\bin\setenv.bat C:\WinDDK\6000\ chk AMD64 WNET && CD \Projects\win-pvdrivers.hg && build -cZg"
cmd /C "C:\WinDDK\6000\bin\setenv.bat C:\WinDDK\6000\ chk WNET && CD \Projects\win-pvdrivers.hg && build -cZg"
cmd /C "C:\WinDDK\6000\bin\setenv.bat C:\WinDDK\6000\ chk WXP && CD \Projects\win-pvdrivers.hg && build -cZg"
xcopy target\* dist /E /EXCLUDE:exclude.txt /D /Y
copy doc\*.txt dist
