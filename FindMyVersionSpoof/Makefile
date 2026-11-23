TARGET := iphone:clang:7.0:5.0
INSTALL_TARGET_PROCESSES = FindMyiPhone FindMyFriends


include $(THEOS)/makefiles/common.mk

TWEAK_NAME = FindMyVersionSpoof

FindMyVersionSpoof_FILES = Tweak.x
FindMyVersionSpoof_CFLAGS = -fobjc-arc -Wno-gcc-compat

include $(THEOS_MAKE_PATH)/tweak.mk
