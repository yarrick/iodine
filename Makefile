CC = gcc
OUT = dnstun
OBJS = dnstun.o tun.o

LDFLAGS = 
CFLAGS = -c -g -Wall 

$(OUT): $(OBJS)
	$(CC) $(OBJS) -o $(OUT) $(LDFLAGS)

%.o : %.c %.h
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(OUT)
	rm -f *~
	rm -f *.o
	rm -f *.core

run: $(OUT)
	./$(OUT)
