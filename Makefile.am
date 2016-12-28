## Process this file with automake to produce Makefile.in

################################################################
##                           shared                           ##
################################################################

AM_CPPFLAGS = -D$(OS)
AM_CFLAGS = -g -Wall -pedantic


################################################################
##                            docs                            ##
################################################################

dist_man_MANS = man/iodine.8
dist_doc_DATA = CHANGELOG README.md README-android.txt README-win32.txt	\
 TODO doc/proto_00000402.txt doc/proto_00000500.txt			\
 doc/proto_00000502.txt


################################################################
##                            misc                            ##
################################################################

EXTRA_DIST = .travis.yml doc/iodine-server.service	\
 doc/iodine-server.socket doc/iodine.te src/Android.mk


################################################################
##                            src/                            ##
################################################################

sbin_PROGRAMS = iodine iodined

COMMONSRC0 = src/base32.c src/base64.c src/common.c src/dns.c	\
 src/encoding.c src/login.c src/md5.c src/read.c

COMMONSRC = $(COMMONSRC0) src/base128.c src/tun.c src/base64u.c	\
 src/base64u.h src/android_dns.h src/base128.h src/base32.h	\
 src/base64.h src/common.h src/dns.h src/encoding.h src/login.h	\
 src/md5.h src/read.h src/tun.h src/version.h src/windows.h

iodine_SOURCES = $(COMMONSRC) src/iodine.c src/client.c src/util.c	\
 src/client.h src/util.h

iodined_SOURCES = $(COMMONSRC) src/iodined.c src/user.c	\
 src/fw_query.c src/fw_query.h src/user.h

EXTRA_DIST += src/android_dns.h src/base128.h src/base32.h		\
 src/base64.h src/client.h src/common.h src/dns.h src/encoding.h	\
 src/fw_query.h src/login.h src/md5.h src/read.h src/tun.h src/user.h	\
 src/util.h src/version.h src/windows.h

src/base64u.c: src/base64.c
	@echo Making $@
	@echo '/* No use in editing, produced by Makefile! */' > $@
	sed -e 's/\([Bb][Aa][Ss][Ee]64\)/\1u/g ; s/0123456789+/0123456789_/' < $< >> $@

src/base64u.h: src/base64.h
	@echo Making $@
	@echo '/* No use in editing, produced by Makefile! */' > $@
	sed -e 's/\([Bb][Aa][Ss][Ee]64\)/\1u/g ; s/0123456789+/0123456789_/' < $< >> $@

BUILT_SOURCES = src/base64u.c src/base64u.h

MOSTLYCLEANFILES = src/base64u.c src/base64u.h

clean-local:
	@echo Clean Android Stuff
	-rm -rf src/obj src/libs


################################################################
##                           tests/                           ##
################################################################

if HAVE_CHECK
TESTS = test-iodine
noinst_PROGRAMS = test-iodine

test_iodine_SOURCES = tests/test.c tests/base32.c tests/base64.c	\
 tests/common.c tests/read.c tests/dns.c tests/encoding.c		\
 tests/login.c tests/user.c tests/fw_query.c $(COMMONSRC0) src/user.c	\
 src/fw_query.c

EXTRA_DIST += tests/test.h

test_iodine_LDADD = $(CHECK_LIBS)
test_iodine_CFLAGS = $(AM_CFLAGS) $(CHECK_CFLAGS)
test_iodine_CPPFLAGS = $(AM_CPPFLAGS) -I src
endif


################################################################
##                      Ancient History                       ##
################################################################

# retain compatibility with former target "test"

.PHONY: test
test: check

# Compile for Android.

# It is likely possible to tweak autotools into supporting this
# configuration, once that is tested the below should be removed.

.PHONY: cross-android
cross-android: src/base64u.c src/base64u.h
	(cd src; ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=Android.mk)

.PHONY: cross-android-dist
cross-android-dist:
	rm -rf iodine-latest-android*
	mkdir -p iodine-latest-android/armeabi iodine-latest-android/x86
	$(MAKE) cross-android TARGET_ARCH_ABI=armeabi
	cp src/libs/armeabi/* iodine-latest-android/armeabi
	$(MAKE) cross-android TARGET_ARCH_ABI=x86
	cp src/libs/x86/* iodine-latest-android/x86
	cp README.md README-android.txt CH* TO* iodine-latest-android/
	echo "Create date: " > iodine-latest-android/VERSION
	date >> iodine-latest-android/VERSION
	echo "Git version: " >> iodine-latest-android/VERSION
	echo $(GITREVISION) >> iodine-latest-android/VERSION
	zip -r iodine-latest-android.zip iodine-latest-android

# Compile for MS Windows.

# This platform is supported by autotools, so the below should be removed once
# autotools is tested in that configuration.

.PHONY: cross-mingw
cross-mingw: 
	echo "WARNING:"
	echo "This make target is unlikely to work properly."
	echo "Cross compilation is supported by autotools."
	echo "  ./configure --build=turingmachine-unknown-linux-gnu --host=mingw32"
	$(MAKE) OS=WINDOWS32 CC=i686-mingw32-gcc all

.PHONY: cross-mingw-dist
cross-mingw-dist: cross-mingw
	rm -rf iodine-latest-win32*
	mkdir -p iodine-latest-win32/bin
	for i in `ls bin`; do cp bin/$$i iodine-latest-win32/bin/$$i.exe; done
	cp /usr/i686-mingw32/usr/bin/zlib1.dll iodine-latest-win32/bin/
	cp README.md README-win32.txt CH* TO* iodine-latest-win32/
	echo "Create date: " > iodine-latest-win32/VERSION
	date >> iodine-latest-win32/VERSION
	echo "Git version: " >> iodine-latest-win32/VERSION
	echo $(GITREVISION) >> iodine-latest-win32/VERSION
	zip -r iodine-latest-win32.zip iodine-latest-win32
