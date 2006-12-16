CC = gcc
TEST = test
OBJS = test.o base32.o
SRCOBJS = ../src/base32.o

OS = `uname | tr "a-z" "A-Z"`

LDFLAGS =  -L/usr/local/lib -lcheck
CFLAGS = -g -Wall -D$(OS) -I../src -I/usr/local/include

all: $(TEST)
	./$(TEST)

$(TEST): $(OBJS) $(SRCOBJS)
	@echo Linking test
	@$(CC) -o $@ $(SRCOBJS) $(OBJS) $(LDFLAGS) 

.c.o: 
	@echo Building $<
	@$(CC) $(CFLAGS) -c $<


clean:
	@echo "Cleaning..."
	@rm -f *~ *.core $(TESTS) $(OBJS)

