
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

get-sources: $(FILES)
get-sources:
	git submodule update --init --recursive

verify-sources:
	@true

OUTDIR = $(PWD)/bin/$(ARCH)

all: $(OUTDIR) $(FILES_UPSTREAM:%.tar=%/.unpacked) $(OUTDIR)/xencontrol.dll $(OUTDIR)/libxenvchan.dll include/xencontrol.h include/xeniface_ioctls.h

CFLAGS += -I . -I $(PWD)/include -I$(PWD)/xeniface/include  -I $(PWD)/$(ARCH) -I $(DDKPATH) -std=c11 -fgnu89-inline -DUNICODE -D_UNICODE $(DEBUG) -mwindows -D_WIN32_WINNT=0x0600 -D__MINGW__ -D_INC_TCHAR -DNO_SHLWAPI_STRFCNS
LDFLAGS += -L $(PWD)/$(ARCH) -L $(PWD)/xeniface/xeniface/$(ARCH) -lxencontrol -Wl,--as-needed -Wl,--no-insert-timestamp

$(OUTDIR):
	mkdir -p $(OUTDIR)

$(PWD)/xeniface/xeniface/$(ARCH)/xencontrol.dll:
	cd xeniface/src/xencontrol/ && \
    $(CC) xencontrol.c -lsetupapi -I ../../include -DXENCONTROL_EXPORTS -DUNICODE -shared -o $@

$(OUTDIR)/xencontrol.dll: $(PWD)/xeniface/xeniface/$(ARCH)/xencontrol.dll
	cp $^ $@

$(OUTDIR)/libxenvchan.dll:
	cd src/libxenvchan && \
	$(CC) *.c $(CFLAGS) $(LDFLAGS) -DXENVCHAN_EXPORTS -D_NTOS_ -shared -o $@

%/.unpacked: %-$(PVDRIVERS_VERSION).tar
	tar xvf $< -C $*
	cp $*/$*/$(ARCH)/* $(OUTDIR)/
	touch $@

include/%.h: xeniface/include/%.h
	cp $^ $@
