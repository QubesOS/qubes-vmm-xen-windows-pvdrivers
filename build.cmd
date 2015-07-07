@echo off

if "%python3%" == "" goto :py_error

if "%WIN_BUILD_TYPE%" == "fre" set USER_BUILD_TYPE=Release
if "%WIN_BUILD_TYPE%" == "chk" set USER_BUILD_TYPE=Debug

set USER_ARCH=%DDK_ARCH%
if "%DDK_ARCH%" == "x86" set USER_ARCH=Win32

:: build the PV drivers
set OBJECT_PREFIX=Qubes
set VS=%VS_PATH%
set KIT=%WDK8_PATH%

:: Patch Xenbus device IDs in xenvbd and xenvif INFs.
:: They should bind to the current latest Xenbus PDO revision.
:: Xennet binds to xenvif so no changes needed there.
powershell -Command "(Get-Content xenvbd\src\xenvbd.inf) -replace 'DEV_VBD&REV_00000001', 'DEV_VBD&REV_00000028' | Set-Content xenvbd\src\xenvbd.inf"
powershell -Command "(Get-Content xenvif\src\xenvif.inf) -replace 'DEV_VIF&REV_00000004', 'DEV_VIF&REV_00000028' | Set-Content xenvif\src\xenvif.inf"

:: Patch evtchn interface headers to only support version 5 to reduce number of PDO revisions and avoid failed assertions.
:: Upstream drivers use version 3 so don't change it in xenbus repo (yet).
powershell -Command "(Get-Content xenbus\include\evtchn_interface.h) -replace '#define XENBUS_EVTCHN_INTERFACE_VERSION_MIN 3', '#define XENBUS_EVTCHN_INTERFACE_VERSION_MIN 5' | Set-Content xenbus\include\evtchn_interface.h"
xcopy /y xenbus\include\evtchn_interface.h xeniface\include\evtchn_interface.h
xcopy /y xenbus\include\evtchn_interface.h xenvbd\include\evtchn_interface.h
xcopy /y xenbus\include\evtchn_interface.h xenvif\include\evtchn_interface.h

call :build_driver xenbus
call :build_driver xeniface
call :build_driver xenvbd
call :build_driver xenvif
call :build_driver xennet

:: build the main project
call "%VS_PATH%\VC\vcvarsall.bat" x86
cd vs2013
msbuild.exe /m:1 /p:Configuration="%USER_BUILD_TYPE%" /p:Platform="%USER_ARCH%" /t:"Build" vmm-xen-windows-pvdrivers.sln
if errorlevel 1 call :build_error "main solution %DDK_ARCH%"
cd ..

:: copy driver libs up
xcopy /y xeniface\include\xencontrol.h include\
xcopy /y xeniface\include\xeniface_ioctls.h include\
xcopy /y /s xeniface\xencontrol\* bin\

echo *** Build OK ***
exit /b 0

:build_driver
echo * Building %1...
cd %1
%python3% ..\build.py %1 %WIN_BUILD_TYPE% %DDK_ARCH%
if errorlevel 1 call :build_error %1
cd ..
:: the following line returns to the caller
goto :eof

:py_error
echo.
echo *** ERROR: Set %%PYTHON3%% variable to the full path to a Python 3 executable ***
echo.
exit 1

:build_error:
echo.
echo *** BUILD FAILED for %1 ***
echo.
exit 1
