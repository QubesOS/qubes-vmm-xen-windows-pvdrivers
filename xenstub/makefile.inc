_LNG=$(LANGUAGE)
STAMP=stampinf -f $@ -a $(_BUILDARCH) -d * -v $(VERSION)

..\Target\$(DDK_TARGET_OS)\$(INF_NAME).inf: $(INF_NAME).inx sources ..\common.inc
    copy $(@B).inx $@
    $(STAMP)
