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

xcopy /D xenhide\%BUILDDIR%\xenhide.sys xenpci\%BUILDDIR%
xcopy /D %BASEDIR%\redist\wdf\%_BUILDARCH%\WdfCoInstaller01007.dll xenpci\%BUILDDIR%

IF NOT EXIST SIGN_CONFIG.BAT GOTO DONT_SIGN
CALL SIGN_CONFIG.BAT
%DDK_PATH%\bin\selfsign\inf2cat /driver:xenpci\%BUILDDIR% /os:%SIGN_OS%
%DDK_PATH%\bin\selfsign\signtool sign /v /n %CERT_NAME% /t http://timestamp.verisign.com/scripts/timestamp.dll xenpci\%BUILDDIR%\xenpci.sys xenpci\%BUILDDIR%\WdfCoInstaller01007.dll xenpci\%BUILDDIR%\xenpci.cat

%DDK_PATH%\bin\selfsign\inf2cat /driver:xennet\%BUILDDIR% /os:%SIGN_OS%
%DDK_PATH%\bin\selfsign\signtool sign /v /n %CERT_NAME% /t http://timestamp.verisign.com/scripts/timestamp.dll xennet\%BUILDDIR%\xennet.sys xennet\%BUILDDIR%\xennet.cat

%DDK_PATH%\bin\selfsign\inf2cat /driver:xenvbd\%BUILDDIR% /os:%SIGN_OS%
%DDK_PATH%\bin\selfsign\signtool sign /v /n %CERT_NAME% /t http://timestamp.verisign.com/scripts/timestamp.dll xenvbd\%BUILDDIR%\xenvbd.sys xenvbd\%BUILDDIR%\xenvbd.cat

%DDK_PATH%\bin\selfsign\inf2cat /driver:xenscsi\%BUILDDIR% /os:%SIGN_OS%
%DDK_PATH%\bin\selfsign\signtool sign /v /n %CERT_NAME% /t http://timestamp.verisign.com/scripts/timestamp.dll xenscsi\%BUILDDIR%\xenscsi.sys xenscsi\%BUILDDIR%\xenscsi.cat

:DONT_SIGN
