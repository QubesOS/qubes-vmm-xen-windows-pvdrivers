@echo off

if "%python3%" == "" goto :py_error

if "%WIN_BUILD_TYPE%" == "fre" set USER_BUILD_TYPE=Release
if "%WIN_BUILD_TYPE%" == "chk" set USER_BUILD_TYPE=Debug

set USER_ARCH=%DDK_ARCH%
if "%DDK_ARCH%" == "x86" set USER_ARCH=Win32

:: build the PV drivers
set VS=%VS_PATH%
set KIT=%WDK10_PATH%
set DPINST_REDIST=%WDK8_PATH%\redist\DIFx\dpinst\EngMui
set SYMBOL_SERVER=C:\Symbols
set PVDRIVERS_VERSION=8.2.1
set XENPV_USE_UPSTREAM_BUILD=1

call :build_driver xeniface

if "%XENPV_USE_UPSTREAM_BUILD%" == "1" goto :unpack_upstream
call :build_driver xenbus
call :build_driver xenvbd
call :build_driver xenvif
call :build_driver xennet
goto :main_project

:unpack_upstream

tar xvf xenbus-%PVDRIVERS_VERSION%.tar -C xenbus
tar xvf xeniface-%PVDRIVERS_VERSION%.tar -C xeniface
tar xvf xenvbd-%PVDRIVERS_VERSION%.tar -C xenvbd
tar xvf xenvif-%PVDRIVERS_VERSION%.tar -C xenvif
tar xvf xennet-%PVDRIVERS_VERSION%.tar -C xennet

:main_project
:: build the main project
call "%VS_PATH%\VC\Auxiliary\Build\vcvarsall.bat" x86
cd vs2017
msbuild.exe /m:1 /p:Configuration="%USER_BUILD_TYPE%" /p:Platform="%USER_ARCH%" /t:"Build" vmm-xen-windows-pvdrivers.sln
if errorlevel 1 call :build_error "main solution %DDK_ARCH%"
cd ..

:: copy driver libs up
xcopy /y xeniface\include\xencontrol.h include\
xcopy /y xeniface\include\xeniface_ioctls.h include\
xcopy /y xeniface\xeniface\%DDK_ARCH%\xencontrol* bin\%DDK_ARCH%\

echo *** Build OK ***
exit /b 0

:build_driver
echo * Building %1...
cd %1
%python3% ..\build.py %1 %WIN_BUILD_TYPE% "Windows 7" %DDK_ARCH% nosdv
if errorlevel 1 call :build_error %1
cd ..
:: the following line returns to the caller
goto :eof

:py_error
echo.
echo *** ERROR: Set %%PYTHON3%% variable to the full path to a Python 3 executable ***
echo.
exit 1

:build_error
echo.
echo *** BUILD FAILED for %1 ***
echo.
exit 1
