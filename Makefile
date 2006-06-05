CC = gcc
OUT = dnstun
OBJS = dnstun.o tun.o dns.o

OS = `uname | tr "a-z" "A-Z"`

LDFLAGS = 
CFLAGS = -c -g -Wall -D$(OS)

all: stateos $(OUT)

stateos:
	@echo OS is $(OS)

$(OUT): $(OBJS)
	@echo LD $@
	@$(CC) $(OBJS) -o $(OUT) $(LDFLAGS)

.c.o: 
	@echo CC $<
	@$(CC) $(CFLAGS) $< -o $@

clean:
	@echo "Cleaning..."
	@rm -f $(OUT) *~ *.o *.core

run: $(OUT)
	./$(OUT)
