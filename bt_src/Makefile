# File: Makefile
# Copyright (C) 2007-2008, Marvell International Ltd.
#

CC=		$(CROSS_COMPILE)gcc
LD=		$(CROSS_COMPILE)ld

BACKUP=		/root/backup
YMD=		`date +%Y%m%d%H%M`

#############################################################################
# Configuration Options
#############################################################################

# Debug Option
# DEBUG LEVEL n/1:
# n: NO DEBUG
# 1: PRINTM(MSG,...), PRINTM(FATAL,...), PRINTM(WARN,...) and PRINTM(INFO,...)
CONFIG_DEBUG=1


#############################################################################
# Select Platform Tools
#############################################################################

MODEXT = ko

KERNELVERSION_X86 := 	$(shell uname -r)
KERNELDIR=/lib/modules/$(KERNELVERSION_X86)/build



PLATFORM=syskt
EXTRA_CFLAGS += -I$(PWD)/../io/sdio/$(PLATFORM) -I$(PWD)/../io/sdio/$(PLATFORM)/h
EXTRA_CFLAGS += -I$(PWD)/bt
LD += -S

BINDIR = ../bin_sd8787_bt

#############################################################################
# Compiler Flags
#############################################################################
	EXTRA_CFLAGS += -DFPNUM='"64"'

ifeq ($(CONFIG_DEBUG),1)
	EXTRA_CFLAGS += -DDEBUG_LEVEL1
endif


#############################################################################
# Make Targets
#############################################################################

ifneq ($(KERNELRELEASE),)

BTOBJS = bt/bt_main.o bt/bt_sdiom.o bt/bt_proc.o

obj-m := bt8xxx.o
bt8xxx-objs := $(BTOBJS)

obj-m += ../io/sdio/$(PLATFORM)/


# Otherwise we were called directly from the command line; invoke the kernel build system.
else
default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
endif

###############################################################

export		CC LD EXTRA_CFLAGS KERNELDIR

echo:

build:		echo default

	@if [ ! -d $(BINDIR) ]; then \
		mkdir $(BINDIR); \
	fi
	cp -f bt8xxx.$(MODEXT) $(BINDIR)/bt8787.$(MODEXT)

	cp -f ../io/sdio/$(PLATFORM)/mrvlsdio.$(MODEXT) $(BINDIR)/
	cp -f script/sdio_syskt/* $(BINDIR)/

	cp -f README $(BINDIR)

clean:
	-find . -name "*.o" -exec rm {} \;
	-find . -name "*.ko" -exec rm {} \;
	-find . -name ".*.cmd" -exec rm {} \;
	-find . -name "*.mod.c" -exec rm {} \;
	-find . -name "*.symvers" -exec rm {} \;
	-rm -rf .tmp_versions
	$(MAKE) -C ../io/sdio/$(PLATFORM) $@



install: default

distclean:
	-find . -name "*.o" -exec rm {} \;
	-find . -name "*.orig" -exec rm {} \;
	-find . -name "*.swp" -exec rm {} \;
	-find . -name "*.*~" -exec rm {} \;
	-find . -name "*~" -exec rm {} \;
	-find . -name "*.d" -exec rm {} \;
	-find . -name "*.a" -exec rm {} \;
	-find . -name "tags" -exec rm {} \;
	-find . -name ".*" -exec rm -rf 2> /dev/null \;
	-find . -name "*.ko" -exec rm {} \;
	-find . -name ".*.cmd" -exec rm {} \;
	-find . -name "*.mod.c" -exec rm {} \;
	-rm -rf .tmp_versions
# End of file;
