_LNG=$(LANGUAGE)
STAMP=stampinf -f $@ -a $(_BUILDARCH) -d * -v $(GPLPV_VERSION) -k $(KMDF_VERSION_MAJOR).$(KMDF_VERSION_MINOR)

$(OBJ_PATH)\$(O)\$(TARGETNAME).inf: $(TARGETNAME).inx sources ..\common.inc
    copy $(@B).inx $@
    $(STAMP)
