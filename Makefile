
PVDRIVERS_VERSION = 8.2.1
BASE_URL = https://xenbits.xenproject.org/pvdrivers/win

URLS := $(BASE_URL)/$(PVDRIVERS_VERSION)/xenbus.tar \
		$(BASE_URL)/$(PVDRIVERS_VERSION)/xeniface.tar \
		$(BASE_URL)/$(PVDRIVERS_VERSION)/xenvbd.tar \
		$(BASE_URL)/$(PVDRIVERS_VERSION)/xennet.tar \
		$(BASE_URL)/$(PVDRIVERS_VERSION)/xenvif.tar

FILES_UPSTREAM := $(notdir $(URLS))
FILES := $(patsubst %.tar,%-$(PVDRIVERS_VERSION).tar,$(FILES_UPSTREAM))

$(FILES): %-$(PVDRIVERS_VERSION).tar:
	echo $*
	wget -O $@.UNTRUSTED "$(filter %$*.tar,$(URLS))"
	grep $@ sources|sed 's:$@:$@.UNTRUSTED:' | sha512sum -c -
	mv $@.UNTRUSTED $@

$(info $(FILES))
$(info $(URLS))
get-sources: $(FILES)
get-sources:
	git submodule update --init --recursive
