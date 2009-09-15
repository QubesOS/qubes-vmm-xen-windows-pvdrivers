@ECHO OFF
IF %_BUILDARCH%==x86 (SET BUILDDIR=obj%BUILD_ALT_DIR%\i386) ELSE (SET BUILDDIR=obj%BUILD_ALT_DIR%\amd64)
IF %DDK_TARGET_OS%==WinXP SET SIGN_OS=XP_X86
IF %DDK_TARGET_OS%%_BUILDARCH%==WinNETx86 SET SIGN_OS=Server2003_X86
IF %DDK_TARGET_OS%%_BUILDARCH%==WinNETAMD64 SET SIGN_OS=XP_X64,Server2003_X64
IF %DDK_TARGET_OS%%_BUILDARCH%==WinLHx86 SET SIGN_OS=Vista_X86,Server2008_X86
IF %DDK_TARGET_OS%%_BUILDARCH%==WinLHAMD64 SET SIGN_OS=Vista_X64,Server2008_X64

ECHO DDK_TARGET_OS=%DDK_TARGET_OS%
ECHO _BUILDARCH=%_BUILDARCH%
ECHO BUILDDIR=%BUILDDIR%
ECHO SIGN_OS=%SIGN_OS%

xcopy /D coinst\%BUILDDIR%\coinst.dll xenvbd\%BUILDDIR%
move xenvbd\%BUILDDIR%\coinst.dll xenvbd\%BUILDDIR%\xencoinst.dll
xcopy /D %BASEDIR%\redist\wdf\%_BUILDARCH%\WdfCoInstaller01007.dll xenpci\%BUILDDIR%
xcopy /D %BASEDIR%\redist\wdf\%_BUILDARCH%\WdfCoInstaller01007.dll xenusb\%BUILDDIR%

REM IF NOT EXIST SIGN_CONFIG.BAT GOTO DONT_SIGN
REM CALL SIGN_CONFIG.BAT

SET CERT_NAME=GPLPV_Test_Cert

REM %DDK_PATH%\bin\selfsign\signtool sign /v /s PrivateCertStore /n %CERT_NAME% /t http://timestamp.verisign.com/scripts/timestamp.dll xenpci\%BUILDDIR%\xenpci.sys xenpci\%BUILDDIR%\WdfCoInstaller01007.dll
%DDK_PATH%\bin\selfsign\signtool sign /v /s PrivateCertStore /n %CERT_NAME% /t http://timestamp.verisign.com/scripts/timestamp.dll xenpci\%BUILDDIR%\xenpci.sys
%DDK_PATH%\bin\selfsign\inf2cat /driver:xenpci\%BUILDDIR% /os:%SIGN_OS%
%DDK_PATH%\bin\selfsign\signtool sign /v /s PrivateCertStore /n %CERT_NAME% /t http://timestamp.verisign.com/scripts/timestamp.dll xenpci\%BUILDDIR%\xenpci.cat

%DDK_PATH%\bin\selfsign\signtool sign /v /s PrivateCertStore /n %CERT_NAME% /t http://timestamp.verisign.com/scripts/timestamp.dll xennet\%BUILDDIR%\xennet.sys
%DDK_PATH%\bin\selfsign\inf2cat /driver:xennet\%BUILDDIR% /os:%SIGN_OS%
%DDK_PATH%\bin\selfsign\signtool sign /v /s PrivateCertStore /n %CERT_NAME% /t http://timestamp.verisign.com/scripts/timestamp.dll xennet\%BUILDDIR%\xennet.cat

%DDK_PATH%\bin\selfsign\signtool sign /v /s PrivateCertStore /n %CERT_NAME% /t http://timestamp.verisign.com/scripts/timestamp.dll xenvbd\%BUILDDIR%\xenvbd.sys xenvbd\%BUILDDIR%\xencoinst.dll
%DDK_PATH%\bin\selfsign\inf2cat /driver:xenvbd\%BUILDDIR% /os:%SIGN_OS%
%DDK_PATH%\bin\selfsign\signtool sign /v /s PrivateCertStore /n %CERT_NAME% /t http://timestamp.verisign.com/scripts/timestamp.dll xenvbd\%BUILDDIR%\xenvbd.cat

%DDK_PATH%\bin\selfsign\signtool sign /v /s PrivateCertStore /n %CERT_NAME% /t http://timestamp.verisign.com/scripts/timestamp.dll xenscsi\%BUILDDIR%\xenscsi.sys
%DDK_PATH%\bin\selfsign\inf2cat /driver:xenscsi\%BUILDDIR% /os:%SIGN_OS%
%DDK_PATH%\bin\selfsign\signtool sign /v /s PrivateCertStore /n %CERT_NAME% /t http://timestamp.verisign.com/scripts/timestamp.dll xenscsi\%BUILDDIR%\xenscsi.cat

REM %DDK_PATH%\bin\selfsign\signtool sign /v /s PrivateCertStore /n %CERT_NAME% /t http://timestamp.verisign.com/scripts/timestamp.dll xenusb\%BUILDDIR%\xenusb.sys xenusb\%BUILDDIR%\WdfCoInstaller01007.dll
%DDK_PATH%\bin\selfsign\signtool sign /v /s PrivateCertStore /n %CERT_NAME% /t http://timestamp.verisign.com/scripts/timestamp.dll xenusb\%BUILDDIR%\xenusb.sys
%DDK_PATH%\bin\selfsign\inf2cat /driver:xenusb\%BUILDDIR% /os:%SIGN_OS%
%DDK_PATH%\bin\selfsign\signtool sign /v /s PrivateCertStore /n %CERT_NAME% /t http://timestamp.verisign.com/scripts/timestamp.dll xenusb\%BUILDDIR%\xenusb.cat

:DONT_SIGN
