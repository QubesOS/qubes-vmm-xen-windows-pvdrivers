@ECHO OFF
IF NOT EXIST SIGN_CONFIG.BAT GOTO DONT_SIGN
CALL SIGN_CONFIG.BAT
%DDK_PATH%\bin\selfsign\inf2cat /driver:target/%1 /os:%2
%DDK_PATH%\bin\selfsign\signtool sign /v /n %CERT_NAME% /t http://timestamp.verisign.com/scripts/timestamp.dll target\%1\xengplpv.cat
:DONT_SIGN
