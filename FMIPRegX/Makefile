TARGET := iphone:clang:7.0:6.0
INSTALL_TARGET_PROCESSES = aosnotifyd


include $(THEOS)/makefiles/common.mk

TWEAK_NAME = FMIPRegX

FMIPRegX_FILES = Tweak.x
FMIPRegX_CFLAGS = -fobjc-arc -Wno-gcc-compat

include $(THEOS_MAKE_PATH)/tweak.mk
