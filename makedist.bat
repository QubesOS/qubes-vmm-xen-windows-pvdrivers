@echo off
IF NOT EXIST set_ddk_path.bat ECHO >set_ddk_path.bat SET DDK_PATH=C:\WinDDK\6001.18002

CALL set_ddk_path.bat

cmd /C "%DDK_PATH%\bin\setenv.bat %DDK_PATH%\ fre WXP && CD \Projects\win-pvdrivers.hg && build -cZg && call wix.bat"
rem CALL sign_sys.bat winxp i386 XP_X86
rem CALL sign_inf.bat winxp XP_X86

cmd /C "%DDK_PATH%\bin\setenv.bat %DDK_PATH%\ fre WNET && CD \Projects\win-pvdrivers.hg && build -cZg && call wix.bat"
rem CALL sign_sys.bat winnet i386 Server2003_X86
rem CALL sign_inf.bat winnet Server2003_X64
rem "%WIX%\bin\candle" installer.wxs -ext "%WIX%\bin\WixUIExtension.dll" -ext "%WIX%\bin\WixDifxAppExtension.dll" -ext "%WIX%\bin\WixIIsExtension.dll"
rem "%WIX%\bin\light.exe" -o gplpv_%BUILD_ALT_DIR%.msi installer.wixobj "%WIX%\bin\difxapp_x86.wixlib" -ext "%WIX%\bin\WixUIExtension.dll" -ext "%WIX%\bin\WixDifxAppExtension.dll" -ext "%WIX%\bin\WixIIsExtension.dll"

cmd /C "%DDK_PATH%\bin\setenv.bat %DDK_PATH%\ fre x64 WNET && CD \Projects\win-pvdrivers.hg && build -cZg && call wix.bat"
rem CALL sign_sys.bat winnet amd64 Server2003_X64
rem CALL sign_inf.bat winnet Server2003_X64
rem "%WIX%\bin\candle" installer.wxs -ext "%WIX%\bin\WixUIExtension.dll" -ext "%WIX%\bin\WixDifxAppExtension.dll" -ext "%WIX%\bin\WixIIsExtension.dll"
rem "%WIX%\bin\light.exe" -o gplpv_%BUILD_ALT_DIR%.msi installer.wixobj "%WIX%\bin\difxapp_x86.wixlib" -ext "%WIX%\bin\WixUIExtension.dll" -ext "%WIX%\bin\WixDifxAppExtension.dll" -ext "%WIX%\bin\WixIIsExtension.dll"

cmd /C "%DDK_PATH%\bin\setenv.bat %DDK_PATH%\ fre WLH && CD \Projects\win-pvdrivers.hg && build -cZg && call wix.bat"
rem CALL sign_sys.bat winlh i386 Server2008_X86
rem CALL sign_inf.bat winlh Server2008_X64
rem "%WIX%\bin\candle" installer.wxs -ext "%WIX%\bin\WixUIExtension.dll" -ext "%WIX%\bin\WixDifxAppExtension.dll" -ext "%WIX%\bin\WixIIsExtension.dll"
rem "%WIX%\bin\light.exe" -o gplpv_%BUILD_ALT_DIR%.msi installer.wixobj "%WIX%\bin\difxapp_x86.wixlib" -ext "%WIX%\bin\WixUIExtension.dll" -ext "%WIX%\bin\WixDifxAppExtension.dll" -ext "%WIX%\bin\WixIIsExtension.dll"

cmd /C "%DDK_PATH%\bin\setenv.bat %DDK_PATH%\ fre x64 WLH && CD \Projects\win-pvdrivers.hg && build -cZg && call wix.bat"
rem CALL sign_sys.bat winlh amd64 Server2008_X64
rem CALL sign_inf.bat winlh Server2008_X64
rem "%WIX%\bin\candle" installer.wxs -ext "%WIX%\bin\WixUIExtension.dll" -ext "%WIX%\bin\WixDifxAppExtension.dll" -ext "%WIX%\bin\WixIIsExtension.dll"
rem "%WIX%\bin\light.exe" -o gplpv_%BUILD_ALT_DIR%.msi installer.wixobj "%WIX%\bin\difxapp_x86.wixlib" -ext "%WIX%\bin\WixUIExtension.dll" -ext "%WIX%\bin\WixDifxAppExtension.dll" -ext "%WIX%\bin\WixIIsExtension.dll"

cmd /C "%DDK_PATH%\bin\setenv.bat %DDK_PATH%\ chk WXP && CD \Projects\win-pvdrivers.hg && build -cZg && call wix.bat"
rem CALL sign_sys.bat winxp i386 XP_X86
rem CALL sign_inf.bat winxp XP_X86
rem "%WIX%\bin\candle" installer.wxs -ext "%WIX%\bin\WixUIExtension.dll" -ext "%WIX%\bin\WixDifxAppExtension.dll" -ext "%WIX%\bin\WixIIsExtension.dll"
rem "%WIX%\bin\light.exe" -o gplpv_%BUILD_ALT_DIR%.msi installer.wixobj "%WIX%\bin\difxapp_x86.wixlib" -ext "%WIX%\bin\WixUIExtension.dll" -ext "%WIX%\bin\WixDifxAppExtension.dll" -ext "%WIX%\bin\WixIIsExtension.dll"

cmd /C "%DDK_PATH%\bin\setenv.bat %DDK_PATH%\ chk WNET && CD \Projects\win-pvdrivers.hg && build -cZg && call wix.bat"
rem CALL sign_sys.bat winnet i386 Server2003_X86
rem CALL sign_inf.bat winnet Server2003_X64
rem "%WIX%\bin\candle" installer.wxs -ext "%WIX%\bin\WixUIExtension.dll" -ext "%WIX%\bin\WixDifxAppExtension.dll" -ext "%WIX%\bin\WixIIsExtension.dll"
rem "%WIX%\bin\light.exe" -o gplpv_%BUILD_ALT_DIR%.msi installer.wixobj "%WIX%\bin\difxapp_x86.wixlib" -ext "%WIX%\bin\WixUIExtension.dll" -ext "%WIX%\bin\WixDifxAppExtension.dll" -ext "%WIX%\bin\WixIIsExtension.dll"

cmd /C "%DDK_PATH%\bin\setenv.bat %DDK_PATH%\ chk x64 WNET && CD \Projects\win-pvdrivers.hg && build -cZg && call wix.bat"
rem CALL sign_sys.bat winnet amd64 Server2003_X64
rem CALL sign_inf.bat winnet Server2003_X64
rem "%WIX%\bin\candle" installer.wxs -ext "%WIX%\bin\WixUIExtension.dll" -ext "%WIX%\bin\WixDifxAppExtension.dll" -ext "%WIX%\bin\WixIIsExtension.dll"
rem "%WIX%\bin\light.exe" -o gplpv_%BUILD_ALT_DIR%.msi installer.wixobj "%WIX%\bin\difxapp_x86.wixlib" -ext "%WIX%\bin\WixUIExtension.dll" -ext "%WIX%\bin\WixDifxAppExtension.dll" -ext "%WIX%\bin\WixIIsExtension.dll"

cmd /C "%DDK_PATH%\bin\setenv.bat %DDK_PATH%\ chk WLH && CD \Projects\win-pvdrivers.hg && build -cZg && call wix.bat"
rem CALL sign_sys.bat winlh i386 Server2008_X86
rem CALL sign_inf.bat winlh Server2008_X64
rem "%WIX%\bin\candle" installer.wxs -ext "%WIX%\bin\WixUIExtension.dll" -ext "%WIX%\bin\WixDifxAppExtension.dll" -ext "%WIX%\bin\WixIIsExtension.dll"
rem "%WIX%\bin\light.exe" -o gplpv_%BUILD_ALT_DIR%.msi installer.wixobj "%WIX%\bin\difxapp_x86.wixlib" -ext "%WIX%\bin\WixUIExtension.dll" -ext "%WIX%\bin\WixDifxAppExtension.dll" -ext "%WIX%\bin\WixIIsExtension.dll"

cmd /C "%DDK_PATH%\bin\setenv.bat %DDK_PATH%\ chk x64 WLH && CD \Projects\win-pvdrivers.hg && build -cZg && call wix.bat"
rem CALL sign_sys.bat winlh amd64 Server2008_X64
rem CALL sign_inf.bat winlh Server2008_X64
rem "%WIX%\bin\candle" installer.wxs -ext "%WIX%\bin\WixUIExtension.dll" -ext "%WIX%\bin\WixDifxAppExtension.dll" -ext "%WIX%\bin\WixIIsExtension.dll"
rem "%WIX%\bin\light.exe" -o gplpv_%BUILD_ALT_DIR%.msi installer.wixobj "%WIX%\bin\difxapp_x86.wixlib" -ext "%WIX%\bin\WixUIExtension.dll" -ext "%WIX%\bin\WixDifxAppExtension.dll" -ext "%WIX%\bin\WixIIsExtension.dll"

rem IF NOT EXIST SIGN_CONFIG.BAT GOTO DONT_SIGN
rem CALL SIGN_CONFIG.BAT
rem %DDK_PATH%\bin\selfsign\certmgr -put -r %CA_CERT_LOCATION% -c -s %CA_CERT_STORE% -n %CA_CERT_NAME% ca.cer
rem :DONT_SIGN
