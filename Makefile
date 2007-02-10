PREFIX=/usr/local

INSTALL=/usr/bin/install
INSTALL_FLAGS=

MKDIR=mkdir
MKDIR_FLAGS=-p

RM=rm
RM_FLAGS=-f

all: 
	@(cd src; make all)

install: all
	$(MKDIR) $(MKDIR_FLAGS) $(PREFIX)/sbin
	$(INSTALL) $(INSTALL_FLAGS) bin/iodine $(PREFIX)/sbin/iodine
	$(INSTALL) $(INSTALL_FLAGS) bin/iodined $(PREFIX)/sbin/iodined
	$(MKDIR) $(MKDIR_FLAGS) $(PREFIX)/man/man8
	$(INSTALL) $(INSTALL_FLAGS) man/iodine.8 $(PREFIX)/man/man8/iodine.8

uninstall:
	$(RM) $(RM_FLAGS) $(PREFIX)/sbin/iodine
	$(RM) $(RM_FLAGS) $(PREFIX)/sbin/iodined
	$(RM) $(RM_FLAGS) $(PREFIX)/man/man8/iodine.8
	
test: all
	@(cd tests; make all)

clean:
	@echo "Cleaning..."
	@(cd src; make clean)
	@(cd tests; make clean)
	@rm -rf bin

