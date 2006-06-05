CC = gcc
OUT = dnstun
OBJS = dnstun.o tun.o

OS = `uname | tr "a-z" "A-Z"`

LDFLAGS = 
CFLAGS = -c -g -Wall -D$(OS)

all: stateos $(OUT)

stateos:
	@echo OS is $(OS)

$(OUT): $(OBJS)
	@$(CC) $(OBJS) -o $(OUT) $(LDFLAGS)

.c.o: 
	@echo Compile $@
	@$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(OUT)
	rm -f *~
	rm -f *.o
	rm -f *.core

run: $(OUT)
	./$(OUT)
