#
# Copyright (C) 2018-2019 Intel Corporation
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

ifeq (, $(filter $(MAKECMDGOALS), clean distclean))
ifeq ("$(wildcard config.mk config.h)", "")
$(error Run ./configure before invoking make)
endif
include config.mk
endif

#
# Flags for compilation
#
CFLAGS += $(patsubst %,-I%,$(INCLUDES))
CFLAGS += $(patsubst %,-D%,$(DEFINES))

OBJDIR = .obj/
LIBOBJDIR = .libobj/
TARGET = sedcli
LIB = libsed
#
# Files to be compiled

LIBOBJS = sed.o
LIBOBJS += sed_util.o
ifndef CONFIG_OPAL_DRIVER
LIBOBJS += nvme_access.o
LIBOBJS += nvme_pt_ioctl.o
LIBOBJS += opal_parser.o
else
LIBOBJS += sed_ioctl.o
endif

OBJS = argp.o
OBJS += sedcli_main.o
OBJS += sedcli_util.o

ifdef CONFIG_KMIP
KMIP_OBJS = argp.o
KMIP_OBJS += metadata_serializer.o
KMIP_OBJS += config_file.o
KMIP_OBJS += crypto_lib.o
endif

ALL_TARGETS = $(TARGET)-static $(TARGET)-dynamic
ifdef CONFIG_KMIP
ALL_TARGETS += $(TARGET)-kmip.a
endif

all: $(ALL_TARGETS)
	@ln -sf $(TARGET)-static $(TARGET)

$(TARGET)-static: $(TARGET).a $(LIB).a
	@echo "  LD " $@
	@$(CC) $(TARGET).a $(LDFLAGS) -Wl,-Bstatic -lsed -Wl,-Bdynamic -o $@

$(TARGET)-dynamic: $(TARGET).a $(LIB).so
	@echo "  LD " $@
	@$(CC) $(TARGET).a $(LDFLAGS) -lsed -o $@

$(TARGET).a: $(patsubst %,$(OBJDIR)%,$(OBJS))
	@echo "  AR " $@
	@ar rcs $@ $^

$(TARGET)-kmip.a: $(patsubst %,$(OBJDIR)%,$(KMIP_OBJS))
	@echo "  AR " $@
	@ar rcs $@ $(patsubst %,$(OBJDIR)%,$(KMIP_OBJS))

#
# Static library
#
$(LIB).a: $(patsubst %,$(LIBOBJDIR)%,$(LIBOBJS))
	@echo "  AR " $@
	@ar rcs $@ $^

#
# Shared library
#
$(LIB).so: $(LIB).a
	@echo "  LD " $@
	@$(CC) -shared -Wl,-soname,$@.1 -Wl,--whole-archive $(LIB).a -Wl,--no-whole-archive -o $@.1.0.1
	@ln -sf $@.1.0.1 $@.1
	@ln -sf $@.1.0.1 $@

#
# Main targets for compilation
#
$(OBJDIR)%.o: %.c
	@echo "  CC " $<
	@mkdir -p $(dir $@)
	@$(CC) -c $(CFLAGS) -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"

$(LIBOBJDIR)%.o: lib/%.c
	@echo "  CC " $<
	@mkdir -p $(dir $@)
	@$(CC) -c $(CFLAGS) -shared -fPIC -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"

clean:
	@echo "  CLEAN "
	@rm -f *.a $(TARGET)-kmip $(TARGET)-static $(TARGET)-dynamic $(TARGET) *.so*
	@rm -fr $(OBJDIR) $(LIBOBJDIR)
	@rm -f $(shell find -name \*.d) $(shell find -name \*.o)

distclean: clean
	@rm -f config.log config.mk config.h

install:
	@echo " Installing $(TARGET)"
	install -m 755 $(TARGET)-dynamic /usr/sbin/$(TARGET)
	install -m 755 $(LIB).so.1.0.1 $(LIB_DIR)
	ln -sf $(LIB_DIR)/$(LIB).so.1.0.1 $(LIB_DIR)/$(LIB).so.1
	install -m 644 ../doc/$(TARGET).8 /usr/share/man/man8/$(TARGET).8

uninstall:
	@echo "  Removing $(TARGET)"
	-rm /usr/sbin/$(TARGET)
	-rm $(LIB_DIR)/$(LIB).so*
	-rm /usr/share/man/man8/$(TARGET).8

.PHONY: clean all distclean install uninstall
