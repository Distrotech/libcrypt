
CC:=gcc
CFLAGS=-g -O2

prefix:=/usr
bindir=$(prefix)/bin
libdir=$(prefix)/lib
incdir=$(prefix)/include
docdir=$(prefix)/share/doc/Cygwin
DLLVER=0
EXE=.exe

STATICLIB=libcrypt.a
SHAREDLIB=cygcrypt-$(DLLVER).dll
IMPORTLIB=libcrypt.dll.a

APPS=crypt$(EXE)
LIBS=$(STATICLIB) $(SHAREDLIB)

all: $(APPS) $(LIBS)

crypt$(EXE): crypt.o $(LIBS)
	$(CC) -static -o $@ crypt.o -L. -lcrypt

$(STATICLIB): encrypt.o
	ar rv $@ encrypt.o

$(SHAREDLIB): encrypt.o
	$(CC) -shared -Wl,--out-implib=$(IMPORTLIB) -Wl,--export-all \
	$^ -o $@

encrypt.o: encrypt.h

distclean: clean

clean:
	-rm *.o *.exe *.a *.dll

install: all
	install -d $(DESTDIR)$(bindir)
	install -d $(DESTDIR)$(libdir)
	install -d $(DESTDIR)$(incdir)
	install -d $(DESTDIR)$(docdir)
	install -m 755 -s $(APPS)      $(DESTDIR)$(bindir)
	install -m 644 encrypt.h       $(DESTDIR)$(incdir)/crypt.h
	install -m 644 $(STATICLIB)    $(DESTDIR)$(libdir)
	install -m 644 $(IMPORTLIB)    $(DESTDIR)$(libdir)
	install -m 755 -s $(SHAREDLIB) $(DESTDIR)$(bindir)
	install -m 644 crypt.README    $(DESTDIR)$(docdir)

