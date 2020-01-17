IDIR =../include
CC=gcc
CFLAGS=-I$(IDIR) -Wall

ODIR=src/

LIBS=-lssl -lcrypto -lpam

ifeq ($(SERVER_AS_CLIENT),ON)
CFLAGS += $(pkg-config libnotify --cflags) -D SERVER_AS_CLIENT=1
LIBS += $(pkg-config libnotify --libs)
endif

_DEPS = 
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

_OBJ = server.o 
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

$(ODIR)/%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

notiserver: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

$PREFIX=/usr
install:
	cp notiserver $PREFIX/bin
uninstall:
	rm $PREFIX/bin/notiserver
	
.PHONY: clean

clean:
	rm -f $(ODIR)/*.o notiserver
