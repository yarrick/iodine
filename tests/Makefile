CC = gcc
TESTSUITE = tester
TESTOBJS = test.o ../src/dns.o ../src/read.o ../src/encoding.o

OS = `uname | tr "a-z" "A-Z"`

LDFLAGS =  -lz
CFLAGS = -c -g -Wall -D$(OS)

all: $(TESTSUITE) 

test:	$(TESTSUITE)
	@./$(TESTSUITE)

$(TESTSUITE): $(TESTOBJS)
	@echo LD $@
	@$(CC) $(TESTOBJS) -o $(TESTSUITE) $(LDFLAGS)
	@echo Running tests... 
	@./$(TESTSUITE)

.c.o: 
	@echo CC $<
	@$(CC) $(CFLAGS) $< -o $@

clean:
	@echo "Cleaning tests/"
	@rm -f $(TESTSUITE) *~ *.o *.core

