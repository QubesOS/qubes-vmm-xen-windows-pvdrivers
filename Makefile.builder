ifeq ($(PACKAGE_SET),vm)
WIN_SOURCE_SUBDIRS = .
endif

# only for drivers
WIN_PREBUILD_CMD = set_version.bat
# Signing is required for drivers
WIN_PREBUILD_CMD += && (if not defined CERT_FILENAME echo Signing required for PV drivers && exit 1)
WIN_OUTPUT_LIBS = tools/libs
WIN_OUTPUT_HEADERS = tools/include
