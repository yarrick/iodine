

iodine - https://code.kryo.se/iodine

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

4. Add a IP rule to use main routing table

        ip rule add priority 10 lookup main

5. Run iodine (see the man page for parameters)

		./iodine ...

== Building iodine for Android:
1. Note the path where you unpacked the Android NDK

2. Download and unpack the iodine sources

3. Copy the ubuntu-android-aarch64.ini or macos-android-aarch64.ini from
   the .github subdirectory into the iodine directory, calling it android.ini

4. Open android.ini and edit the ndk_path to point to your NDK location

5. Build with meson using the cross file:
   ```
   meson setup build-android --cross-file android.ini
   cd build-android
   ninja
   ```
