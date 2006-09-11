CC = gcc
CLIENT = iodine
CLIENTOBJS = iodine.o tun.o dns.o read.o encoding.o
SERVER = iodined
SERVEROBJS = iodined.o tun.o dns.o read.o encoding.o
TESTSUITE = tester
TESTOBJS = test.o dns.o read.o encoding.o

OS = `uname | tr "a-z" "A-Z"`

LDFLAGS =  -lz
CFLAGS = -c -g -Wall -D$(OS)

all: stateos $(CLIENT) $(SERVER) $(TESTSUITE) 

test:	$(TESTSUITE)
	@./$(TESTSUITE)

stateos:
	@echo OS is $(OS)

$(CLIENT): $(CLIENTOBJS)
	@echo LD $@
	@$(CC) $(CLIENTOBJS) -o $(CLIENT) $(LDFLAGS)

$(SERVER): $(SERVEROBJS)
	@echo LD $@
	@$(CC) $(SERVEROBJS) -o $(SERVER) $(LDFLAGS)

$(TESTSUITE): $(TESTOBJS)
	@echo LD $@
	@$(CC) $(TESTOBJS) -o $(TESTSUITE) $(LDFLAGS)
	@echo Running tests... 
	@./$(TESTSUITE)

.c.o: 
	@echo CC $<
	@$(CC) $(CFLAGS) $< -o $@

clean:
	@echo "Cleaning..."
	@rm -f $(CLIENT) $(SERVER) $(TESTSUITE) *~ *.o *.core

