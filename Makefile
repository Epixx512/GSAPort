TARGET := iphone:clang:7.0:5.0
INSTALL_TARGET_PROCESSES = Preferences accountsd gamed FindMyiPhone FindMyFriends imagent
ARCHS = armv7 armv7s arm64


include $(THEOS)/makefiles/common.mk

TWEAK_NAME = GSAPort

GSAPort_FILES = Tweak.x polyfill.x
GSAPort_CFLAGS = -fobjc-arc -Wno-gcc-compat -I$(THEOS_PROJECT_DIR)/openssl/include
GSAPort_LDFLAGS = $(THEOS_PROJECT_DIR)/openssl/lib/libcrypto.a -framework IOKit -framework CFNetwork -lz
GSAPort_FRAMEWORKS = UIKit

include $(THEOS_MAKE_PATH)/tweak.mk
SUBPROJECTS += FindMyRegX
SUBPROJECTS += FindMyVersionSpoof
include $(THEOS_MAKE_PATH)/aggregate.mk
