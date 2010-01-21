# File: Makefile
#
# Copyright (C) 2008-2009, Marvell International Ltd. 
#
# This software file (the "File") is distributed by Marvell International 
# Ltd. under the terms of the GNU General Public License Version 2, June 1991 
# (the "License").  You may use, redistribute and/or modify this File in 
# accordance with the terms and conditions of the License, a copy of which 
# is available by writing to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA or on the
# worldwide web at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
#
# A copy of the GPL is available in file gpl-2.0.txt accompanying in this 
# deliverables.
#
# THE FILE IS DISTRIBUTED AS-IS, WITHOUT WARRANTY OF ANY KIND, AND THE 
# IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE 
# ARE EXPRESSLY DISCLAIMED.  The License provides additional details about 
# this warranty disclaimer.

CC=		$(CROSS_COMPILE)gcc
LD=		$(CROSS_COMPILE)ld
BACKUP=		/root/backup
YMD=		`date +%Y%m%d%H%M`

#############################################################################
# Configuration Options
#############################################################################

# Debug Option
# DEBUG LEVEL n/1/2:
# n: NO DEBUG
# 1: Only PRINTM(MMSG,...), PRINTM(MFATAL,...), ...
# 2: All PRINTM()
CONFIG_DEBUG=1

# Proc debug file
CONFIG_PROC_DEBUG=y

# Re-association in driver
CONFIG_REASSOCIATION=y

# Manufacturing firmware support
CONFIG_MFG_CMD_SUPPORT=y

# Big-endian platform
CONFIG_BIG_ENDIAN=n

# Enable SDIO multi-port Tx aggregation
CONFIG_SDIO_MULTI_PORT_TX_AGGR=y

# Enable SDIO multi-port Rx aggregation
CONFIG_SDIO_MULTI_PORT_RX_AGGR=y


#############################################################################
# Select Platform Tools
#############################################################################

MODEXT = ko
EXTRA_CFLAGS += -I$(PWD)/mlan
EXTRA_CFLAGS += -DLINUX


KERNELVERSION_X86 := 	$(shell uname -r)
KERNELDIR=/lib/modules/$(KERNELVERSION_X86)/build
LD += -S
PLATFORM=syskt
EXTRA_CFLAGS += -I$(PWD)/../io/sdio/$(PLATFORM) -I$(PWD)/../io/sdio/$(PLATFORM)/h
BINDIR = ../bin_sd8787

#############################################################################
# Compiler Flags
#############################################################################

	EXTRA_CFLAGS += -I$(KERNELDIR)/include

	EXTRA_CFLAGS += -DFPNUM='"64"'

ifeq ($(CONFIG_DEBUG),1)
	EXTRA_CFLAGS += -DDEBUG_LEVEL1
endif

ifeq ($(CONFIG_DEBUG),2)
	EXTRA_CFLAGS += -DDEBUG_LEVEL1
	EXTRA_CFLAGS += -DDEBUG_LEVEL2
	DBG=	-dbg
endif

ifeq ($(CONFIG_PROC_DEBUG),y)
	EXTRA_CFLAGS += -DPROC_DEBUG
	export CONFIG_PROC_DEBUG
endif

ifeq ($(CONFIG_REASSOCIATION),y)
	EXTRA_CFLAGS += -DREASSOCIATION
endif

ifeq ($(CONFIG_MFG_CMD_SUPPORT),y)
	EXTRA_CFLAGS += -DMFG_CMD_SUPPORT
endif

ifeq ($(CONFIG_BIG_ENDIAN),y)
	EXTRA_CFLAGS += -DBIG_ENDIAN
endif

ifeq ($(CONFIG_SDIO_MULTI_PORT_TX_AGGR),y)
	EXTRA_CFLAGS += -DSDIO_MULTI_PORT_TX_AGGR
endif

ifeq ($(CONFIG_SDIO_MULTI_PORT_RX_AGGR),y)
	EXTRA_CFLAGS += -DSDIO_MULTI_PORT_RX_AGGR
endif


#############################################################################
# Make Targets
#############################################################################

ifneq ($(KERNELRELEASE),)

MOALOBJS =	mlinux/moal_main.o \
		mlinux/moal_ioctl.o \
		mlinux/moal_shim.o

MLANOBJS =	mlan/mlan_shim.o mlan/mlan_init.o \
		mlan/mlan_txrx.o \
		mlan/mlan_cmdevt.o mlan/mlan_misc.o \
		mlan/mlan_module.o

MLANOBJS += mlan/mlan_wmm.o
MLANOBJS += mlan/mlan_sdio.o
MLANOBJS += mlan/mlan_11n_aggr.o
MLANOBJS += mlan/mlan_11n_rxreorder.o
MLANOBJS += mlan/mlan_11n.o
MLANOBJS += mlan/mlan_11d.o
MLANOBJS += mlan/mlan_scan.o
MLANOBJS += mlan/mlan_join.o
MLANOBJS += mlan/mlan_cfp.o \
            mlan/mlan_sta_ioctl.o \
            mlan/mlan_sta_rx.o \
            mlan/mlan_sta_tx.o \
            mlan/mlan_sta_event.o \
            mlan/mlan_sta_cmd.o \
            mlan/mlan_sta_cmdresp.o
MOALOBJS += mlinux/moal_priv.o \
            mlinux/moal_wext.o
MLANOBJS += mlan/mlan_11h.o
MLANOBJS += mlan/mlan_meas.o


ifdef CONFIG_PROC_FS
MOALOBJS += mlinux/moal_proc.o
ifeq ($(CONFIG_PROC_DEBUG),y)
MOALOBJS += mlinux/moal_debug.o
endif
endif

obj-m := mlan.o
mlan-objs := $(MLANOBJS)
MOALOBJS += mlinux/moal_sdio.o
obj-m += sd8xxx.o
sd8xxx-objs := $(MOALOBJS)
obj-m += ../io/sdio/$(PLATFORM)/


# Otherwise we were called directly from the command line; invoke the kernel build system.
else

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

endif

###############################################################

export		CC LD EXTRA_CFLAGS KERNELDIR

.PHONY: mapp/mlanconfig mapp/mlan2040coex clean distclean
	@echo "Finished Making Marvell Wlan Linux Driver"

mapp/mlanconfig:
	$(MAKE) -C $@
mapp/mlan2040coex:
	$(MAKE) -C $@

echo:

build:		echo default

	@if [ ! -d $(BINDIR) ]; then \
		mkdir $(BINDIR); \
	fi 
	cp -f mlan.$(MODEXT) $(BINDIR)/mlan$(DBG).$(MODEXT)
	cp -f sd8xxx.$(MODEXT) $(BINDIR)/sd8787$(DBG).$(MODEXT)
	cp -f ../io/sdio/$(PLATFORM)/mrvlsdio.$(MODEXT) $(BINDIR)/
	cp -rpf script/sdio_syskt/* $(BINDIR)/

	cp -f README $(BINDIR)
	$(MAKE) -C mapp/mlanconfig $@ INSTALLDIR=$(BINDIR)
	$(MAKE) -C mapp/mlan2040coex $@ INSTALLDIR=$(BINDIR)

clean:
	-find . -name "*.o" -exec rm {} \;
	-find . -name "*.ko" -exec rm {} \;
	-find . -name ".*.cmd" -exec rm {} \;
	-find . -name "*.mod.c" -exec rm {} \;
	-find . -name "Module.symvers" -exec rm {} \;
	-find . -name "Module.markers" -exec rm {} \;
	-find . -name "modules.order" -exec rm {} \;
	-rm -rf .tmp_versions
	$(MAKE) -C mapp/mlanconfig $@
	$(MAKE) -C mapp/mlan2040coex $@
	$(MAKE) -C ../io/sdio/$(PLATFORM) $@

install: default

	cp -f mlan.$(MODEXT) $(INSTALLDIR)/mlan$(DBG).$(MODEXT)
	cp -f ../io/sdio/$(PLATFORM)/mrvlsdio.$(MODEXT) $(INSTALLDIR)
	cp -f sd8xxx.$(MODEXT) $(INSTALLDIR)/sd8787$(DBG).$(MODEXT)
	echo "sd8787 Driver Installed"

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
	$(MAKE) -C mapp/mlanconfig $@
	$(MAKE) -C mapp/mlan2040coex $@

# End of file
