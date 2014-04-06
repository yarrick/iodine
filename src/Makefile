COMMONOBJS = tun.o dns.o read.o encoding.o login.o base32.o base64.o base64u.o base128.o md5.o common.o
CLIENTOBJS = iodine.o client.o util.o
CLIENT = ../bin/iodine
SERVEROBJS = iodined.o user.o fw_query.o
SERVER = ../bin/iodined

OS := $(shell echo $(TARGETOS) | tr "a-z" "A-Z")
ARCH := $(shell uname -m)
HEAD_COMMIT := $(shell git rev-parse --short HEAD)

LIBPATH = -L.
OS_CPPFLAGS := $(shell sh osflags $(TARGETOS) cppflags)
OS_CFLAGS   := $(shell sh osflags $(TARGETOS) cflags)
OS_LDFLAGS  := $(shell sh osflags $(TARGETOS) link)
CPPFLAGS = -D$(OS) -DGITREVISION=\"$(HEAD_COMMIT)\" $(OS_CPPFLAGS)
CFLAGS += -g -Wall -pedantic $(OS_CFLAGS)
LDFLAGS +=  -lz $(OS_LDFLAGS) $(LIBPATH)

all: stateos $(CLIENT) $(SERVER)

stateos:
	@echo OS is $(OS), arch is $(ARCH)

iodine:  $(COMMONOBJS) $(CLIENTOBJS)
iodined: $(COMMONOBJS) $(SERVEROBJS)
$(CLIENT): iodine;  mkdir -p ../bin && cp -a $< $@
$(SERVER): iodined; mkdir -p ../bin && cp -a $< $@

base64u.o client.o iodined.o: base64u.h
base64u.c: base64.c
	@echo Making $@
	echo '/* No use in editing, produced by Makefile! */' > $@
	sed -e 's/\([Bb][Aa][Ss][Ee]64\)/\1u/g ; s/0123456789+/0123456789_/' < base64.c >> $@
base64u.h: base64.h
	@echo Making $@
	echo '/* No use in editing, produced by Makefile! */' > $@
	sed -e 's/\([Bb][Aa][Ss][Ee]64\)/\1u/g ; s/0123456789+/0123456789_/' < base64.h >> $@

clean:
	@echo "Cleaning src/"
	rm -f iodine iodined
	rm -f $(CLIENT){,.exe} $(SERVER){,.exe} *~ *.o *.core base64u.*
	rm -rf obj libs #android stuff
