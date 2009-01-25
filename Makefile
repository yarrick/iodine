prefix=/usr/local
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

cross-mingw: 
	@(cd src; $(MAKE) TARGETOS=windows32 CC=i686-mingw32-gcc all)

cross-mingw-dist: cross-mingw
	@rm -rf iodine-latest-win32*
	@mkdir -p iodine-latest-win32/bin
	@for i in `ls bin`; do cp bin/$$i iodine-latest-win32/bin/$$i.exe; done
	@cp /usr/i686-mingw32/usr/bin/zlib1.dll iodine-latest-win32/bin
	@cp README* CH* TO* iodine-latest-win32
	@echo "Create date: " > iodine-latest-win32/VERSION
	@date >> iodine-latest-win32/VERSION
	@echo "SVN version: " >> iodine-latest-win32/VERSION
	@svnversion >> iodine-latest-win32/VERSION
	@zip -r iodine-latest-win32.zip iodine-latest-win32

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
	@rm -rf bin iodine-latest-win32*

