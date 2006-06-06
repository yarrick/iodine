CC = gcc
DNS = dnstun
DNSOBJS = dnstun.o tun.o dns.o
DNSD = dnstund
DNSDOBJS = dnstund.o tun.o dnsd.o

OS = `uname | tr "a-z" "A-Z"`

LDFLAGS =  -lz
CFLAGS = -c -g -Wall -D$(OS)

all: stateos $(DNS) $(DNSD)

stateos:
	@echo OS is $(OS)

$(DNS): $(DNSOBJS)
	@echo LD $@
	@$(CC) $(DNSOBJS) -o $(DNS) $(LDFLAGS)

$(DNSD): $(DNSDOBJS)
	@echo LD $@
	@$(CC) $(DNSDOBJS) -o $(DNSD) $(LDFLAGS)

.c.o: 
	@echo CC $<
	@$(CC) $(CFLAGS) $< -o $@

clean:
	@echo "Cleaning..."
	@rm -f $(DNS) $(DNSD) *~ *.o *.core

