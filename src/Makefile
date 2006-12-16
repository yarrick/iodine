CC = gcc
CLIENT = ../bin/iodine
CLIENTOBJS = iodine.o tun.o dns.o read.o encoding.o login.o base32.o
SERVER = ../bin/iodined
SERVEROBJS = iodined.o tun.o dns.o read.o encoding.o login.o base32.o

OS = `uname | tr "a-z" "A-Z"`

LDFLAGS =  -lz
CFLAGS = -c -g -Wall -D$(OS)

all: stateos $(CLIENT) $(SERVER) $(TESTSUITE) 

stateos:
	@echo OS is $(OS)

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

