ARCH		= $(shell uname -m | sed s,i[3456789]86,ia32,)

SUBDIRS		= 

LIB_PATH	= /usr/lib64

EFI_INCLUDE	= /usr/include/efi
EFI_INCLUDES	= -nostdinc -I$(EFI_INCLUDE) -I$(EFI_INCLUDE)/$(ARCH) -I$(EFI_INCLUDE)/protocol -Iinclude
EFI_PATH	:= /usr/lib64/gnuefi

LIB_GCC		= $(shell $(CC) -print-libgcc-file-name)
EFI_LIBS	= -lefi -lgnuefi $(LIB_GCC) 
ELF_LIBS	= -lefivar

EFI_CRT_OBJS 	= $(EFI_PATH)/crt0-efi-$(ARCH).o
EFI_LDS		= elf_$(ARCH)_efi.lds

ELF_CFLAGS	= -fpic -fshort-wchar -ggdb -O0 -Wall -Werror
EFI_CFLAGS	= $(ELF_CFLAGS) \
		  -fno-builtin -fno-stack-protector -fno-strict-aliasing \
		  -maccumulate-outgoing-args -mno-mmx -mno-red-zone \
		  -mno-sse \
		  $(EFI_INCLUDES)

ifeq ($(ARCH),x86_64)
	CFLAGS	+= -DEFI_FUNCTION_WRAPPER -DGNU_EFI_USE_MS_ABI
endif
ifneq ($(origin VENDOR_CERT_FILE), undefined)
	CFLAGS += -DVENDOR_CERT_FILE=\"$(VENDOR_CERT_FILE)\"
endif

LDFLAGS		= -nostdlib -znocombreloc -T $(EFI_LDS) -shared -Bsymbolic -L$(EFI_PATH) -L$(LIB_PATH) $(EFI_CRT_OBJS)

VERSION		= 0.1

TARGET	= lockdown.efi lockdown

EFI_OBJS = efi.o
EFI_SOURCES = efi.c

ELF_OBJS = elf.o
ELF_SOURCES = elf.c

all: $(TARGET)

lockdown.so : $(EFI_OBJS) cert.o
	$(LD) -o $@ $(LDFLAGS) $^ $(EFI_LIBS)

lockdown : $(ELF_OBJS) cert.o
	$(CC) $(ELF_CFLAGS) -o $@ $< $(ELF_LIBS)

cert.o : cert.S
	$(CC) $(CFLAGS) -c -o $@ $<

$(EFI_OBJS) : %.o : %.c
	$(CC) $(EFI_CFLAGS) -c -o $@ $^

$(ELF_OBJS) : %.o : %.c
	$(CC) $(ELF_CFLAGS) -c -o $@ $^

%.efi: %.so
	objcopy -j .text -j .sdata -j .data \
		-j .dynamic -j .dynsym  -j .rel \
		-j .rela -j .reloc -j .eh_frame \
		-j .vendor_cert \
		--target=efi-app-$(ARCH) $^ $@
	objcopy -j .text -j .sdata -j .data \
		-j .dynamic -j .dynsym  -j .rel \
		-j .rela -j .reloc -j .eh_frame \
		-j .debug_info -j .debug_abbrev -j .debug_aranges \
		-j .debug_line -j .debug_str -j .debug_ranges \
		--target=efi-app-$(ARCH) $^ $@.debug

clean:
	rm -f $(TARGET) $(ELF_OBJS) $(EFI_OBJS)
	rm -f *.debug *.so *.efi *.tar.*

GITTAG = $(VERSION)

test-archive:
	@rm -rf /tmp/lockdown-$(VERSION) /tmp/lockdown-$(VERSION)-tmp
	@mkdir -p /tmp/lockdown-$(VERSION)-tmp
	@git archive --format=tar $(shell git branch | awk '/^*/ { print $$2 }') | ( cd /tmp/lockdown-$(VERSION)-tmp/ ; tar x )
	@git diff | ( cd /tmp/lockdown-$(VERSION)-tmp/ ; patch -s -p1 -b -z .gitdiff )
	@mv /tmp/lockdown-$(VERSION)-tmp/ /tmp/lockdown-$(VERSION)/
	@git log -1 --pretty=format:%H > /tmp/lockdown-$(VERSION)/commit
	@dir=$$PWD; cd /tmp; tar -c --bzip2 -f $$dir/lockdown-$(VERSION).tar.bz2 lockdown-$(VERSION)
	@rm -rf /tmp/lockdown-$(VERSION)
	@echo "The archive is in lockdown-$(VERSION).tar.bz2"

archive:
	git tag $(GITTAG) refs/heads/master
	@rm -rf /tmp/lockdown-$(VERSION) /tmp/lockdown-$(VERSION)-tmp
	@mkdir -p /tmp/lockdown-$(VERSION)-tmp
	@git archive --format=tar $(GITTAG) | ( cd /tmp/lockdown-$(VERSION)-tmp/ ; tar x )
	@mv /tmp/lockdown-$(VERSION)-tmp/ /tmp/lockdown-$(VERSION)/
	@git log -1 --pretty=format:%H > /tmp/lockdown-$(VERSION)/commit
	@dir=$$PWD; cd /tmp; tar -c --bzip2 -f $$dir/lockdown-$(VERSION).tar.bz2 lockdown-$(VERSION)
	@rm -rf /tmp/lockdown-$(VERSION)
	@echo "The archive is in lockdown-$(VERSION).tar.bz2"
