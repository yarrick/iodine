

iodine - http://code.kryo.se/iodine

***********************************

Extra README file for Android


== Running iodine on Android:
1. Get root access on your android device

2. Find/build a compatible tun.ko for your specific Android kernel

3. Copy tun.ko and the iodine binary to your device:
   (Almost all devices need the armeabi binary. Only Intel powered 
   ones need the x86 build.)

		adb push tun.ko /data/local/tmp
		adb push iodine /data/local/tmp
		adb shell
		su
		cd /data/local/tmp
		chmod 777 iodine

4. Run iodine (see the man page for parameters)

		./iodine ...

For more information: http://blog.bokhorst.biz/5123

== Building iodine for Android:
1. Download and install the Android SDK and NDK

2. Download and unpack the iodine sources

3. Build:
		cd src
		make base64u.h base64u.c
		ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=Android.mk

   or run "make cross-android" in the iodine root directory.
   To build for other archs, specify TARGET_ARCH_ABI: 
		"make cross-android TARGET_ARCH_ABI=x86"

