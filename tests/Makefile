CC = gcc
TEST = test
OBJS = test.o base32.o base64.o read.o dns.o encoding.o login.o user.o 
SRCOBJS = ../src/base32.o  ../src/base64.o ../src/read.o ../src/dns.o ../src/encoding.o ../src/login.o ../src/md5.o ../src/user.o

OS = `uname | tr "a-z" "A-Z"`

LDFLAGS =  -L/usr/local/lib -lcheck
CFLAGS = -g -Wall -D$(OS) -I../src -I/usr/local/include -pedantic

all: $(TEST)
	@./$(TEST)

$(TEST): $(OBJS) $(SRCOBJS)
	@echo LD $(TEST)
	@$(CC) -o $@ $(SRCOBJS) $(OBJS) $(LDFLAGS) 

.c.o: 
	@echo CC $<
	@$(CC) $(CFLAGS) -c $<


clean:
	@echo "Cleaning..."
	@rm -f *~ *.core $(TEST) $(OBJS)

