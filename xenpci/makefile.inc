_LNG=$(LANGUAGE)
STAMP=stampinf -f $@ -a $(_BUILDARCH) -d * -v $(VERSION) -k $(KMDF_VERSION_MAJOR).$(KMDF_VERSION_MINOR)

$(INF_NAME).inf: $(INF_NAME).inx sources ..\common.inc
    copy $(@B).inx $@
    $(STAMP)
