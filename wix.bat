@ECHO OFF
IF "%_BUILDARCH%"=="x86" (SET DIFXLIB=%WIX%bin\difxapp_x86.wixlib) ELSE (SET DIFXLIB=%WIX%bin\difxapp_x64.wixlib)
"%WIX%\bin\candle" installer.wxs -ext "%WIX%\bin\WixUIExtension.dll" -ext "%WIX%\bin\WixDifxAppExtension.dll" -ext "%WIX%\bin\WixIIsExtension.dll"
"%WIX%\bin\light.exe" -o gplpv_%BUILD_ALT_DIR%.msi installer.wixobj "%DIFXLIB%" -ext "%WIX%\bin\WixUIExtension.dll" -ext "%WIX%\bin\WixDifxAppExtension.dll" -ext "%WIX%\bin\WixIIsExtension.dll"
