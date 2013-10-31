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

CFLAGS		= -fpic -fshort-wchar -ggdb -O0 -Wall -Werror
ELF_CFLAGS	= $(CFLAGS) --std=gnu99
EFI_CFLAGS	= $(CFLAGS) \
		  -fno-builtin -fno-stack-protector -fno-strict-aliasing \
		  -maccumulate-outgoing-args -mno-mmx -mno-red-zone \
		  -mno-sse \
		  -DEFI_FUNCTION_WRAPPER -DGNU_EFI_USE_MS_ABI \
		  $(EFI_INCLUDES)

NSS_LIBS	= $(shell pkg-config --libs nss)
NSS_INCL	= $(shell pkg-config --cflags nss)

-include Make.defaults

ifeq "$(origin DB_FILE)" "undefined"
  $(error "DB_FILE must be defined")
endif

ifeq "$(origin KEK_FILE)" "undefined"
  $(error "KEK_FILE must be defined")
endif

ifeq "$(origin PK_FILE)" "undefined"
  $(error "PK_FILE must be defined")
endif

ifeq ($(ARCH),x86_64)
	EFI_CFLAGS	+= -DEFI_FUNCTION_WRAPPER -DGNU_EFI_USE_MS_ABI
endif

LDFLAGS		= -nostdlib -znocombreloc -T $(EFI_LDS) -shared -Bsymbolic -L$(EFI_PATH) -L$(LIB_PATH) $(EFI_CRT_OBJS)

VERSION		= 0.2

TARGET	= lockdown.efi lockdown buildvar assemble

EFI_OBJS = efi.o
EFI_SOURCES = efi.c DB.h KEK.h PK.h

ELF_OBJS = elf.o
ELF_SOURCES = elf.c DB.h KEK.h PK.h

all: $(TARGET)

%.h : %.auth
	xxd -i $^ > $@

$(EFI_OBJS) : $(EFI_SOURCES)

$(ELF_OBJS) : $(ELF_SOURCES)

lockdown.so : $(EFI_OBJS)
	$(LD) -o $@ $(LDFLAGS) $^ $(EFI_LIBS)

lockdown : $(ELF_OBJS)
	$(CC) $(ELF_CFLAGS) -o $@ $< $(ELF_LIBS)

# sample invocation:
# buildvar -d redhatsecureboot003.esl -t "Fri Oct 18 13:55:00 2013" -n PK \
#          -N -B -R --force \
#          -o redhatsecureboot003.unsigned -a redhatsecureboot003.authattr
BUILDVAR_SOURCES = buildvar.c pkcs7.c pkcs7.h wincert.h
buildvar : $(BUILDVAR_SOURCES)
	$(CC) $(ELF_CFLAGS) -I$(EFI_INCLUDE) -I$(EFI_INCLUDE)/$(ARCH) \
		$(NSS_INCL) -o $@ $(filter %.c, $(BUILDVAR_SOURCES)) \
		-lpopt -lefivar $(NSS_LIBS)

# sample invocation:
# ./assemble -n PK -s redhatsecureboot003.unsigned \
# 		   -a redhatsecureboot003.authattr \
# 		   -c redhatsecureboot003.cer \
# 		   -S redhatsecureboot003.sig \
# 		   -o variable
ASSEMBLE_SOURCES = assemble.c pkcs7.c pkcs7.h wincert.h
assemble : $(ASSEMBLE_SOURCES)
	$(CC) $(ELF_CFLAGS) -I$(EFI_INCLUDE) -I$(EFI_INCLUDE)/$(ARCH) \
		$(NSS_INCL) -o $@ $(filter %.c, $(ASSEMBLE_SOURCES)) \
		-lpopt -lefivar $(NSS_LIBS)

cert.o : cert.S pk.bin kek.bin db.bin
	$(CC) $(CFLAGS) -DDB_FILE=\"db.bin\" -DKEK_FILE=\"kek.bin\" -DPK_FILE=\"pk.bin\" -c -o $@ $<

$(EFI_OBJS) : %.o : %.c
	$(CC) $(EFI_CFLAGS) -c -o $@ $(filter %.c, $^)

$(ELF_OBJS) : %.o : %.c
	$(CC) $(ELF_CFLAGS) -c -o $@ $(filter %.c, $^)

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
	@rm -vf $(TARGET) $(ELF_OBJS) $(EFI_OBJS)
	@rm -vf *.debug *.so *.efi *.tar.*
	@rm -vf DB.h KEK.h PK.h

GITTAG = $(VERSION)

tag:
	git tag $(GITTAG) refs/heads/master

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

archive: tag
	@rm -rf /tmp/lockdown-$(VERSION) /tmp/lockdown-$(VERSION)-tmp
	@mkdir -p /tmp/lockdown-$(VERSION)-tmp
	@git archive --format=tar $(GITTAG) | ( cd /tmp/lockdown-$(VERSION)-tmp/ ; tar x )
	@mv /tmp/lockdown-$(VERSION)-tmp/ /tmp/lockdown-$(VERSION)/
	@git log -1 --pretty=format:%H > /tmp/lockdown-$(VERSION)/commit
	@dir=$$PWD; cd /tmp; tar -c --bzip2 -f $$dir/lockdown-$(VERSION).tar.bz2 lockdown-$(VERSION)
	@rm -rf /tmp/lockdown-$(VERSION)
	@echo "The archive is in lockdown-$(VERSION).tar.bz2"
