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

all: 
	@(cd src; make all)

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
	$(RM) $(RM_FLAGS) $(sbindir)/iodine
	$(RM) $(RM_FLAGS) $(sbindir)/iodined
	$(RM) $(RM_FLAGS) $(mandir)/man8/iodine.8
	
test: all
	@(cd tests; make all)

clean:
	@echo "Cleaning..."
	@(cd src; make clean)
	@(cd tests; make clean)
	@rm -rf bin

