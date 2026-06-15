.SUFFIXES:

ifeq ($(strip $(DEVKITPRO)),)
$(error "Please set DEVKITPRO in your environment. export DEVKITPRO=/opt/devkitpro")
endif

TOPDIR ?= $(CURDIR)

#-------------------------------------------------------------------------------
# App metadata
#-------------------------------------------------------------------------------
TARGET      := nxpotify
BUILD       := build
DATA        :=

APP_TITLE   := NXpotify
APP_AUTHOR  := etonedemid
APP_VERSION := 1.3.3.7
APP_ICON    := $(TOPDIR)/meta/icon.jpg

include $(DEVKITPRO)/libnx/switch_rules

ARCH    := -march=armv8-a+crc+crypto -mtune=cortex-a57 -mtp=soft -fPIE
MACHDEP := $(ARCH)

#-------------------------------------------------------------------------------
# Tremor (libvorbisidec) -- portlib if installed, vendor source otherwise
#-------------------------------------------------------------------------------
TREMOR_HDR := $(firstword $(wildcard $(patsubst %,%/include/tremor/ivorbisfile.h,$(PORTLIBS))))

ifeq ($(TREMOR_HDR),)
  $(info Tremor: portlib not found -- building from vendor/tremor/)
  TREMOR_SOURCES := vendor/tremor
  TREMOR_LIB     :=
else
  $(info Tremor: using portlib at $(PORTLIBS))
  TREMOR_SOURCES :=
  TREMOR_LIB     := -lvorbisidec
endif

#-------------------------------------------------------------------------------
# Sources
#-------------------------------------------------------------------------------
SOURCES := src               \
           src/connect       \
           src/discovery     \
           src/olv           \
           src/ui            \
           vendor/cJSON      \
           $(TREMOR_SOURCES)

INCLUDES := src vendor

#-------------------------------------------------------------------------------
# Build flags
#-------------------------------------------------------------------------------
CFLAGS   := -g -Wall -Wextra -O2 $(MACHDEP)     \
            -D_DEFAULT_SOURCE                     \
            -Wno-unused-parameter                 \
            -Wno-missing-field-initializers       \
            -Wno-implicit-fallthrough             \
            -Wno-maybe-uninitialized              \
            -include $(TOPDIR)/src/platform.h

CXXFLAGS := $(CFLAGS) -std=c++17 -fno-exceptions -fno-rtti

ASFLAGS  := $(ARCH)
LDFLAGS   = -specs=$(DEVKITPRO)/libnx/switch.specs -g $(ARCH) -fPIE -Wl,-Map,$(notdir $*.map)

LIBS     := -lSDL2_ttf      \
            -lharfbuzz      \
            -lfreetype      \
            -lpng16         \
            -lbz2           \
            -lSDL2          \
            -lEGL           \
            -lglapi         \
            -ldrm_nouveau   \
            -lcurl          \
            -lmbedtls       \
            -lmbedx509      \
            -lmbedcrypto    \
            -lz             \
            $(TREMOR_LIB)   \
            -logg           \
            -lnx

LIBDIRS  := $(LIBNX) $(PORTLIBS)

#-------------------------------------------------------------------------------
# Two-phase devkitPro build
#-------------------------------------------------------------------------------
ifneq ($(BUILD),$(notdir $(CURDIR)))

export OUTPUT  := $(CURDIR)/$(TARGET)
export TOPDIR  := $(CURDIR)
export DEPSDIR := $(CURDIR)/$(BUILD)

export NROFLAGS += --icon=$(APP_ICON) --nacp=$(OUTPUT).nacp

CFILES   := $(foreach dir,$(SOURCES),$(notdir $(wildcard $(TOPDIR)/$(dir)/*.c)))
CPPFILES := $(foreach dir,$(SOURCES),$(notdir $(wildcard $(TOPDIR)/$(dir)/*.cpp)))
SFILES   := $(foreach dir,$(SOURCES),$(notdir $(wildcard $(TOPDIR)/$(dir)/*.s)))

export OFILES  := $(CPPFILES:.cpp=.o) $(CFILES:.c=.o) $(SFILES:.s=.o)

export INCLUDE := $(foreach dir,$(INCLUDES),-I$(TOPDIR)/$(dir)) \
                  $(foreach dir,$(LIBDIRS),-I$(dir)/include)    \
                  -I$(CURDIR)/$(BUILD)

export LIBPATHS := $(foreach dir,$(LIBDIRS),-L$(dir)/lib)

export VPATH := $(foreach dir,$(SOURCES),$(TOPDIR)/$(dir)) \
                $(foreach dir,$(DATA),$(TOPDIR)/$(dir))

.PHONY: $(BUILD) clean all

all: $(BUILD)

$(BUILD):
	@[ -d $@ ] || mkdir -p $@
	@$(MAKE) --no-print-directory -C $(BUILD) -f $(CURDIR)/Makefile

clean:
	@echo clean ...
	@rm -rf $(BUILD) $(TARGET).elf $(TARGET).nro $(TARGET).nacp

else

CPPFLAGS := $(INCLUDE)
LD       := $(CXX)
DEPENDS  := $(OFILES:.o=.d)

$(OUTPUT).nro : $(OUTPUT).elf $(OUTPUT).nacp
$(OUTPUT).elf : $(OFILES)

-include $(DEPENDS)

endif
