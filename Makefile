CC = gcc
CLIENT = iodine
CLIENTOBJS = iodine.o tun.o dns.o read.o
SERVER = iodined
SERVEROBJS = iodined.o tun.o dns.o read.o

OS = `uname | tr "a-z" "A-Z"`

LDFLAGS =  -lz
CFLAGS = -c -g -Wall -D$(OS)

all: stateos $(CLIENT) $(SERVER)

stateos:
	@echo OS is $(OS)

$(CLIENT): $(CLIENTOBJS)
	@echo LD $@
	@$(CC) $(CLIENTOBJS) -o $(CLIENT) $(LDFLAGS)

$(SERVER): $(SERVEROBJS)
	@echo LD $@
	@$(CC) $(SERVEROBJS) -o $(SERVER) $(LDFLAGS)

.c.o: 
	@echo CC $<
	@$(CC) $(CFLAGS) $< -o $@

clean:
	@echo "Cleaning..."
	@rm -f $(CLIENT) $(SERVER) *~ *.o *.core

