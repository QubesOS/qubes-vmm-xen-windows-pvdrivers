@echo off
IF NOT EXIST set_ddk_path.bat ECHO >set_ddk_path.bat SET DDK_PATH=C:\WinDDK\6001.18001

cmd /C "%DDK_PATH%\bin\setenv.bat %DDK_PATH%\ chk WXP && CD \Projects\win-pvdrivers.hg && build -cZg"
CALL sign_sys.bat winxp i386 XP_X86
CALL sign_inf.bat winxp XP_X86

cmd /C "%DDK_PATH%\bin\setenv.bat %DDK_PATH%\ chk WNET && CD \Projects\win-pvdrivers.hg && build -cZg"
CALL sign_sys.bat winnet i386 Server2003_X86
cmd /C "%DDK_PATH%\bin\setenv.bat %DDK_PATH%\ chk x64 WNET && CD \Projects\win-pvdrivers.hg && build -cZg"
CALL sign_sys.bat winnet amd64 Server2003_X64
CALL sign_inf.bat winnet Server2003_X64

cmd /C "%DDK_PATH%\bin\setenv.bat %DDK_PATH%\ chk WLH && CD \Projects\win-pvdrivers.hg && build -cZg"
CALL sign_sys.bat winlh i386 Server2008_X86
cmd /C "%DDK_PATH%\bin\setenv.bat %DDK_PATH%\ chk x64 WLH && CD \Projects\win-pvdrivers.hg && build -cZg"
CALL sign_sys.bat winlh amd64 Server2008_X64
CALL sign_inf.bat winlh Server2008_X64

IF NOT EXIST SIGN_CONFIG.BAT GOTO DONT_SIGN
CALL SIGN_CONFIG.BAT
%DDK_PATH%\bin\selfsign\certmgr -put -r %CA_CERT_LOCATION% -c -s %CA_CERT_STORE% -n %CA_CERT_NAME% ca.cer
:DONT_SIGN

"%ProgramFiles%\NSIS\makensis.exe" installer.nsi
