CC = gcc
COMMONOBJS = tun.o dns.o read.o encoding.o login.o base32.o base64.o md5.o common.o
CLIENTOBJS = iodine.o
CLIENT = ../bin/iodine
SERVEROBJS = iodined.o user.o fw_query.o
SERVER = ../bin/iodined

OS = `echo $(TARGETOS) | tr "a-z" "A-Z"`
ARCH = `uname -m`

LIBPATH = -L.
LDFLAGS =  -lz `sh osflags $(TARGETOS) link` $(LIBPATH)
CFLAGS = -c -g -Wall -D$(OS) -pedantic `sh osflags $(TARGETOS) cflags`

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

clean:
	@echo "Cleaning src/"
	@rm -f $(CLIENT){,.exe} $(SERVER){,.exe} *~ *.o *.core

