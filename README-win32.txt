

iodine - http://code.kryo.se/iodine

***********************************

Extra README file for Win32 related stuff


== Running iodine on Windows:
1. Install the TAP32 driver 
 http://openvpn.net/index.php/downloads.html 
 choose OpenVPN 2.0.9 Windows Installer, when installing you can
 select to install only the TAP driver.

2. Have one TAP32 interface installed

3. Name the interface "dns"

4. Run iodine/iodined as normal.

5. Enjoy!


== Building on Windows:
You need:
	MinGW, MSYS, GCC, zlib

Then just run make


== Cross-compiling for MinGW:
You need:
	MinGW crosscompiler, crosscompiled zlib

Then run "make cross-mingw"
Note that the binaries will not get a .exe suffix


== Zlib download
You can get zlib for MinGW here (both for native and crosscompile):
http://code.kryo.se/iodine/deps/zlib.zip
Unzip it in your MinGW directory on Windows or in $ROOT/usr for
cross-compile.


== Results of crappy Win32 API:
The following fixable limitations apply:
- The password is shown when entered
- DNS server IP can not be fetched automatically
- Exactly one TAP32 interface must be installed
- The TAP32 interface must be named "dns" and be version 0801
- Server cannot read packet destination address
- Server must be run with /30 netmask (really?)

The following (probably) un-fixable limitations apply:
- Priviligies cannot be dropped
- chroot() cannot be used
- Detaching from terminal not possible

