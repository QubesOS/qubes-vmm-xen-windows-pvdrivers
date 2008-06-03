VERSION=0.9.6.1
TARGETPATH=..\Target\$(DDK_TARGET_OS)
MSC_WARNING_LEVEL=/W4
INCLUDES = ..\common\include;..\common\include\public
TARGETLIBS=$(TARGETLIBS) $(DDK_LIB_PATH)\ntstrsafe.lib
NTTARGETFILES=
