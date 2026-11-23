TARGET := iphone:clang:7.0:6.0
INSTALL_TARGET_PROCESSES = aosnotifyd
ARCHS = armv7 armv7s arm64


include $(THEOS)/makefiles/common.mk

TWEAK_NAME = FindMyRegX

FindMyRegX_FILES = Tweak.x
FindMyRegX_CFLAGS = -fobjc-arc -Wno-gcc-compat

include $(THEOS_MAKE_PATH)/tweak.mk
