COMMONOBJS = tun.o dns.o read.o encoding.o login.o base32.o base64.o base64u.o base128.o md5.o common.o
CLIENTOBJS = iodine.o client.o util.o
CLIENT = ../bin/iodine
SERVEROBJS = iodined.o user.o fw_query.o
SERVER = ../bin/iodined

OS = `echo $(TARGETOS) | tr "a-z" "A-Z"`
ARCH = `uname -m`
HEAD_COMMIT = `git rev-parse --short HEAD`

LIBPATH = -L.
LDFLAGS +=  -lz `sh osflags $(TARGETOS) link` $(LIBPATH)
CFLAGS += -std=c99 -c -g -Wall -D$(OS) -pedantic `sh osflags $(TARGETOS) cflags` -DGITREVISION=\"$(HEAD_COMMIT)\"
CFLAGS += -Wstrict-prototypes -Wtype-limits -Wmissing-declarations -Wmissing-prototypes

all: stateos $(CLIENT) $(SERVER)

stateos:
	@echo OS is $(OS), arch is $(ARCH)

$(CLIENT): $(COMMONOBJS) $(CLIENTOBJS)
	@echo LD $@
	@mkdir -p ../bin
	@$(CC) $(COMMONOBJS) $(CLIENTOBJS) -o $(CLIENT) $(LDFLAGS)

$(SERVER): $(COMMONOBJS) $(SERVEROBJS)
	@echo LD $@
	@mkdir -p ../bin
	@$(CC) $(COMMONOBJS) $(SERVEROBJS) -o $(SERVER) $(LDFLAGS)

.c.o:
	@echo CC $<
	@$(CC) $(CFLAGS) $< -o $@

base64u.c: base64.c
	@echo Making $@
	@echo '/* No use in editing, produced by Makefile! */' > $@
	@sed -e 's/\([Bb][Aa][Ss][Ee]64\)/\1u/g ; s/0123456789+/0123456789_/' < base64.c >> $@

clean:
	@echo "Cleaning src/"
	@rm -f $(CLIENT){,.exe} $(SERVER){,.exe} *~ *.o *.core base64u.*
	@rm -rf obj libs #android stuff

