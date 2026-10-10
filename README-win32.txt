

iodine - https://code.kryo.se/iodine

***********************************

Extra README file for Win32 related stuff


== Running iodine on Windows:

0. You need a 64-bit Windows 7 or newer

1. Run iodine/iodined as normal (see the main README file).
   Run it in a window running as administrator.

2. Enjoy!


== Building on Windows:
You need MSYS2 installed.
Using MSYS2, install the following packages:
* mingw-w64-ucrt-x86_64-toolchain
* mingw-w64-ucrt-x86_64-zlib
* mingw-w64-ucrt-x86_64-meson
* mingw-w64-ucrt-x86_64-check (if you want to build and run the tests)

Open a MinGW UCRT64 console, and switch to the iodine directory. Then run:
meson setup build
cd build
ninja
(For the tests, run: ninja test)

== Cross-compiling for MinGW:
You need:
	MinGW UCRT64 crosscompiler, zlib and meson for UCRT64 (same packages as above)

Run the same commands, as on Windows but use ucrt64-meson instead in the first
case.


== Results of crappy Win32 API:
The following fixable limitations apply:
- Server cannot read packet destination address

The following (probably) un-fixable limitations apply:
- A password entered as -P argument can be shown in process list
- Priviligies cannot be dropped
- chroot() cannot be used
- Detaching from terminal not possible

