#
# iodine for Android
#
# by Marcel Bokhorst
# http://blog.bokhorst.biz/5123/computers-en-internet/iodine-for-android/
#
# cd iodine-0.6.0-rc1/src
# make base64u.h base64u.c
# .../ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=Android.mk
#

LOCAL_PATH:= $(call my-dir)

HEAD_COMMIT = `git rev-parse --short HEAD`

include $(CLEAR_VARS)

LOCAL_MODULE    := iodine
LOCAL_SRC_FILES := tun.c dns.c read.c encoding.c login.c base32.c base64.c base64u.c base128.c md5.c common.c iodine.c client.c util.c
LOCAL_CFLAGS    := -c -DANDROID -DLINUX -DIFCONFIGPATH=\"/system/bin/\" -Wall -DGITREVISION=\"$(HEAD_COMMIT)\"
LOCAL_LDLIBS    := -lz
LOCAL_CFLAGS += -fPIE
LOCAL_LDFLAGS += -fPIE -pie

include $(BUILD_EXECUTABLE)

