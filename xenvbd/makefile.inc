_LNG=$(LANGUAGE)
STAMP=stampinf -f $@ -a $(_BUILDARCH) -d * -v $(VERSION)

$(INF_NAME).inf: $(INF_NAME).inx sources ..\common.inc
    copy $(@B).inx $@
    $(STAMP)
