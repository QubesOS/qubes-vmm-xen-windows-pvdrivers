@echo off

if "%python3%" == "" goto :py_error

if "%WIN_BUILD_TYPE%" == "fre" set USER_BUILD_TYPE=Release
if "%WIN_BUILD_TYPE%" == "chk" set USER_BUILD_TYPE=Debug
set
:: build the PV drivers
set OBJECT_PREFIX=Qubes

call :build_driver xenbus
call :build_driver xeniface
call :build_driver xenvbd
call :build_driver xenvif
call :build_driver xennet

:: build the main project
call "%VS%\VC\vcvarsall.bat" x86
cd vs2013
msbuild.exe /m:1 /p:Configuration="%USER_BUILD_TYPE%" /p:Platform="x64" /t:"Build" vmm-xen-windows-pvdrivers.sln
if errorlevel 1 call :build_error main solution x64
msbuild.exe /m:1 /p:Configuration="%USER_BUILD_TYPE%" /p:Platform="Win32" /t:"Build" vmm-xen-windows-pvdrivers.sln
if errorlevel 1 call :build_error main solution x86
cd ..

:: copy driver libs up
xcopy /y xeniface\include\xencontrol.h include\
xcopy /y xeniface\include\xeniface_ioctls.h include\
xcopy /y /s xeniface\xencontrol\* bin\

exit /b 0

:build_driver
cd %1
%python3% ..\build.py %1 %WIN_BUILD_TYPE%
if errorlevel 1 call :build_error %1
cd ..
:: the following line returns to the caller
goto :eof

:py_error
echo.
echo *** ERROR: Set %%PYTHON3%% variable to the full path to a Python 3 executable ***
echo.
exit /b 1

:build_error:
echo.
echo *** BUILD FAILED for %1 ***
echo.
exit /b 1
