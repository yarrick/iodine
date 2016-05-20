prefix?=/usr/local
sbindir=$(prefix)/sbin
datadir=$(prefix)/share
mandir=$(datadir)/man

DESTDIR=

INSTALL=install
INSTALL_FLAGS=

MKDIR=mkdir
MKDIR_FLAGS=-p

RM=rm
RM_FLAGS=-f

TARGETOS = `uname`

all:
	@(cd src; $(MAKE) TARGETOS=$(TARGETOS) all)
	
debug:
	@(cd src; $(MAKE) TARGETOS=$(TARGETOS) debug)

install: all
	$(MKDIR) $(MKDIR_FLAGS) $(DESTDIR)$(sbindir)
	$(INSTALL) $(INSTALL_FLAGS) bin/iodine $(DESTDIR)$(sbindir)/iodine
	chmod 755 $(DESTDIR)$(sbindir)/iodine
	$(INSTALL) $(INSTALL_FLAGS) bin/iodined $(DESTDIR)$(sbindir)/iodined
	chmod 755 $(DESTDIR)$(sbindir)/iodined
	$(MKDIR) $(MKDIR_FLAGS) $(DESTDIR)$(mandir)/man8
	$(INSTALL) $(INSTALL_FLAGS) man/iodine.8 $(DESTDIR)$(mandir)/man8/iodine.8
	chmod 644 $(DESTDIR)$(mandir)/man8/iodine.8

uninstall:
	$(RM) $(RM_FLAGS) $(DESTDIR)$(sbindir)/iodine
	$(RM) $(RM_FLAGS) $(DESTDIR)$(sbindir)/iodined
	$(RM) $(RM_FLAGS) $(DESTDIR)$(mandir)/man8/iodine.8

test: all
	@echo "!! The check library is required for compiling and running the tests"
	@echo "!! Get it at http://check.sf.net"
	@(cd tests; $(MAKE) TARGETOS=$(TARGETOS) all)

clean:
	@echo "Cleaning..."
	@(cd src; $(MAKE) clean)
	@(cd tests; $(MAKE) clean)
	@rm -rf bin iodine-latest*

#Helper target for windows/android zipfiles
iodine-latest:
	@rm -rf iodine-latest*
	@mkdir -p iodine-latest
	@echo "Create date: " > iodine-latest/VERSION.txt
	@LANG=en_US date >> iodine-latest/VERSION.txt
	@echo "Git version: " >> iodine-latest/VERSION.txt
	@git rev-parse HEAD >> iodine-latest/VERSION.txt
	@for i in README.md CHANGELOG TODO; do cp $$i iodine-latest/$$i.txt; done
	@unix2dos iodine-latest/*

#non-PIE build for old android
cross-android-old:
	@(cd src; $(MAKE) base64u.c base64u.h)
	@(cd src; ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=Android.mk APP_PLATFORM=android-3)

#Position-indepedent build for modern android
cross-android:
	@(cd src; $(MAKE) base64u.c base64u.h)
	@(cd src; ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=Android.mk APP_PLATFORM=android-16)

iodine-latest-android.zip: iodine-latest
	@mv iodine-latest iodine-latest-android
	@mkdir -p iodine-latest-android/pre-kitkat/armeabi
	@mkdir -p iodine-latest-android/pre-kitkat/x86
	@$(MAKE) cross-android-old TARGET_ARCH_ABI=armeabi
	@cp src/libs/armeabi/* iodine-latest-android/pre-kitkat/armeabi
	@$(MAKE) cross-android-old TARGET_ARCH_ABI=x86
	@cp src/libs/x86/* iodine-latest-android/pre-kitkat/x86
	@rm -rf src/libs src/obj
	@mkdir -p iodine-latest-android/armeabi
	@mkdir -p iodine-latest-android/arm64-v8a
	@mkdir -p iodine-latest-android/x86
	@$(MAKE) cross-android TARGET_ARCH_ABI=armeabi
	@cp src/libs/armeabi/* iodine-latest-android/armeabi
	@$(MAKE) cross-android TARGET_ARCH_ABI=arm64-v8a
	@cp src/libs/arm64-v8a/* iodine-latest-android/arm64-v8a
	@$(MAKE) cross-android TARGET_ARCH_ABI=x86
	@cp src/libs/x86/* iodine-latest-android/x86
	@cp README-android.txt iodine-latest-android
	@zip -r iodine-latest-android.zip iodine-latest-android

cross-mingw32:
	@(cd src; $(MAKE) TARGETOS=windows32 CC=i686-w64-mingw32-gcc all)

cross-mingw64:
	@(cd src; $(MAKE) TARGETOS=windows32 CC=x86_64-w64-mingw32-gcc all)

iodine-latest-windows.zip: iodine-latest
	@mv iodine-latest iodine-latest-windows
	@mkdir -p iodine-latest-windows/64bit iodine-latest-windows/32bit
	@(cd src; $(MAKE) TARGETOS=windows32 CC=i686-w64-mingw32-gcc clean all)
	@i686-w64-mingw32-strip bin/iodine*
	@for i in `ls bin`; do cp bin/$$i iodine-latest-windows/32bit/$$i.exe; done
	@cp /usr/i686-w64-mingw32/bin/zlib1.dll iodine-latest-windows/32bit
	@(cd src; $(MAKE) TARGETOS=windows32 CC=x86_64-w64-mingw32-gcc clean all)
	@x86_64-w64-mingw32-strip bin/iodine*
	@for i in `ls bin`; do cp bin/$$i iodine-latest-windows/64bit/$$i.exe; done
	@cp /usr/x86_64-w64-mingw32/bin/zlib1.dll iodine-latest-windows/64bit
	@cp README-win32.txt iodine-latest-windows
	@zip -r iodine-latest-windows.zip iodine-latest-windows

