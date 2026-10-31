

iodine - https://code.kryo.se/iodine

***********************************

Extra README file for Haiku

== Running iodine on Haiku:
1. Create a tunnel device by running
   ifconfig tun/0 up

2. Run iodine as normal, specifying the tunnel name with -d

		./iodine -d tun/0 ...

== Building iodine for Haiku:
1. Install meson with pkgman

2. Build like normal with meson
   ```
   meson setup build
   cd build
   ninja
   ```

3. To run the tests, install packages check and check_devel,
   then run `ninja test` in the build directory.
