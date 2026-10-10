

iodine - https://code.kryo.se/iodine

***********************************

Extra README file for Win32 related stuff


== Running iodine on Windows:

0. You need Windows Vista or newer to run.

1. Install the TAP driver
   https://openvpn.net/index.php/open-source/downloads.html
   Download the OpenVPN TAP driver (under section Tap-windows)
   Problems has been reported with the NDIS6 version (9.2x.y), use the
   NDIS5 version for now if possible (9.9.2 is good).

2. Have at least one TAP32 interface installed. There are scripts for adding
   and removing in the OpenVPN bin directory. If you have more than one
   installed, use -d to specify which. Use double quotes if you have spaces,
   example: iodine.exe -d "Local Area Connection 4" abc.ab

3. Make sure the interface you want to use does not have a default gateway set.

4. Run iodine/iodined as normal (see the main README file).
   Run it in a window running as administrator.

5. Enjoy!


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
- chroot() cannot be used
- Detaching from terminal not possible
- Server on windows must be run with /30 netmask
- Client can only talk to server, not other clients

