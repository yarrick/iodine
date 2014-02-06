

iodine - http://code.kryo.se/iodine

***********************************

Extra README file for Win32 related stuff


== Running iodine on Windows:

0. After iodine 0.6, you need Windows XP or newer to run.

1. Install the TAP32 driver 
   http://openvpn.net/index.php/open-source/downloads.html
   Choose OpenVPN 2.0.9 Windows Installer, when installing you can
   select to install only the TAP driver.

2. Have at least one TAP32 interface installed. There are scripts for adding
   and removing in the OpenVPN bin directory. If you have more than one
   installed, use -d to specify which. Use double quotes if you have spaces,
   example: iodine.exe -d "Local Area Connection 4" abc.ab

3. Make sure the interface you want to use does not have a default gateway set.

4. Run iodine/iodined as normal (see the main README file).
   You may have to run it as administrator depending on user privileges.

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
- Server cannot read packet destination address

The following (probably) un-fixable limitations apply:
- A password entered as -P argument can be shown in process list
- Priviligies cannot be dropped
- chroot() cannot be used
- Detaching from terminal not possible
- Server on windows must be run with /30 netmask
- Client can only talk to server, not other clients

