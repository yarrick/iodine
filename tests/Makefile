TEST = test
OBJS = test.o base32.o base64.o common.o read.o dns.o encoding.o login.o user.o fw_query.o
SRCOBJS = ../src/base32.o  ../src/base64.o ../src/common.o ../src/read.o ../src/dns.o ../src/encoding.o ../src/login.o ../src/md5.o ../src/user.o ../src/fw_query.o

OS = `uname | tr "a-z" "A-Z"`

CHECK_PATH = /usr/local
LDFLAGS = -L$(CHECK_PATH)/lib `pkg-config check --libs` -lpthread `sh ../src/osflags $(TARGETOS) link`
CFLAGS = -std=c99 -g -Wall -D$(OS) `pkg-config check --cflags` -I../src -I$(CHECK_PATH)/include -pedantic `sh ../src/osflags $(TARGETOS) cflags`

all: $(TEST)
	@LD_LIBRARY_PATH=${CHECK_PATH}/lib ./$(TEST)

$(TEST): $(OBJS) $(SRCOBJS)
	@echo LD $(TEST)
	@$(CC) -o $@ $(SRCOBJS) $(OBJS) $(LDFLAGS)

.c.o:
	@echo CC $<
	@$(CC) $(CFLAGS) -c $<

clean:
	@echo "Cleaning tests/"
	@rm -f *~ *.core $(TEST) $(OBJS)

