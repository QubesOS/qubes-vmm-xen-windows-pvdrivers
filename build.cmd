@echo off

if "%python3%" == "" goto :py_error

if "%WIN_BUILD_TYPE%" == "fre" set USER_BUILD_TYPE=Release
if "%WIN_BUILD_TYPE%" == "chk" set USER_BUILD_TYPE=Debug

set USER_ARCH=%DDK_ARCH%
if "%DDK_ARCH%" == "x86" set USER_ARCH=Win32

:: build the PV drivers
set VS=%VS_PATH%
set KIT=%WDK8_PATH%

call :build_driver xenbus
call :build_driver xeniface
call :build_driver xenvbd
call :build_driver xenvif
call :build_driver xennet
:: some weird problem - without this the last build_driver isn't called ("The
:: system cannot find the batch label specified - build_driver")
goto :main_project

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
