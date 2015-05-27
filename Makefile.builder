ifeq ($(PACKAGE_SET),vm)
WIN_COMPILER = custom
WIN_SOURCE_SUBDIRS = .
WIN_BUILD_CMD = build.cmd
WIN_SIGN_CMD = true
WIN_PACKAGE_CMD = true
WIN_OUTPUT_HEADERS = include
WIN_OUTPUT_LIBS = bin
#WIN_PREBUILD_CMD = set_version.bat && powershell -executionpolicy bypass set_version.ps1
endif
