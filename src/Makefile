CC = gcc
CLIENT = ../bin/iodine
CLIENTOBJS = iodine.o tun.o dns.o read.o encoding.o login.o base32.o md5.o common.o
SERVER = ../bin/iodined
SERVEROBJS = iodined.o tun.o dns.o read.o encoding.o login.o base32.o md5.o common.o user.o

OS = `uname | tr "a-z" "A-Z"`
ARCH = `uname -m`

LDFLAGS =  -lz
CFLAGS = -c -g -Wall -D$(OS) -pedantic

all: stateos $(CLIENT) $(SERVER) $(TESTSUITE) 

stateos:
	@echo OS is $(OS), arch is $(ARCH)

$(CLIENT): $(CLIENTOBJS)
	@echo LD $@
	@mkdir -p ../bin
	@$(CC) $(CLIENTOBJS) -o $(CLIENT) $(LDFLAGS)

$(SERVER): $(SERVEROBJS)
	@echo LD $@
	@mkdir -p ../bin
	@$(CC) $(SERVEROBJS) -o $(SERVER) $(LDFLAGS)

.c.o: 
	@echo CC $<
	@$(CC) $(CFLAGS) $< -o $@

clean:
	@echo "Cleaning src/"
	@rm -f $(CLIENT) $(SERVER) *~ *.o *.core

