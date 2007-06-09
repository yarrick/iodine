CC = gcc
COMMONOBJS = tun.o dns.o read.o encoding.o login.o base32.o base64.o md5.o common.o
CLIENTOBJS = iodine.o
CLIENT = ../bin/iodine
SERVEROBJS = iodined.o user.o
SERVER = ../bin/iodined

OS = `uname | tr "a-z" "A-Z"`
ARCH = `uname -m`

LDFLAGS =  -lz
CFLAGS = -c -g -Wall -D$(OS) -pedantic

all: stateos $(CLIENT) $(SERVER) $(TESTSUITE) 

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
	@rm -f $(CLIENT) $(SERVER) *~ *.o *.core

