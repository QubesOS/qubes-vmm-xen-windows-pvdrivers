VERSION=0.6.4.0
TARGETPATH=..\Target\$(DDK_TARGET_OS)
KMDF_VERSION=1
MSC_WARNING_LEVEL=/W4
INCLUDES = ..\common\include;..\common\include\public
TARGETLIBS=$(TARGETLIBS) $(DDK_LIB_PATH)\ntstrsafe.lib
NTTARGETFILES=
#SOURCES_USED=..\common.inc