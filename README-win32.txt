

iodine - http://code.kryo.se/iodine

***********************************

Extra README file for Win32 related stuff



== Building on Windows:
You need:
	MinGW, MSYS, GCC, zlib

Then just run make


== Cross-compiling for MinGW:
You need:
	MinGW crosscompiler, crosscompiled zlib

Then run "make cross-mingw"
Note that the binaries will not get a .exe suffix


== Running iodine on Windows:
The following fixable limitations apply:
- The password is shown when entered
- DNS server IP can not be fetched automatically
- Exactly one TAP32 interface must be installed
- The TAP32 interface must be named "dns"
- Server cannot read packet destination address

The following (probably) un-fixable limitations apply:
- Server must be run with /30 netmask = 1 user at a time
- Priviligies cannot be dropped
- chroot() cannot be used
- Detaching from terminal not possible
