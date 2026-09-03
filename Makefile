TARGET := iphone:clang:7.0:5.0
INSTALL_TARGET_PROCESSES = Preferences accountsd gamed FindMyiPhone FindMyFriends
ARCHS = armv7 arm64


include $(THEOS)/makefiles/common.mk

TWEAK_NAME = GSAPort

GSAPort_FILES = Tweak.x
GSAPort_CFLAGS = -fobjc-arc -isystem /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/6.0/include/ -Wno-gcc-compat -I$(THEOS_PROJECT_DIR)/openssl/include
GSAPort_LDFLAGS = $(THEOS_PROJECT_DIR)/openssl/lib/libcrypto.a -framework IOKit -framework CFNetwork -lz

include $(THEOS_MAKE_PATH)/tweak.mk