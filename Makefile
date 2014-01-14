
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
SHAREDLIB=msys-crypt-$(DLLVER).dll
IMPORTLIB=libcrypt.dll.a

APPS=crypt$(EXE)
LIBS=$(STATICLIB) $(SHAREDLIB)

%.o : %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ -c $<

all: $(APPS) $(LIBS)

crypt$(EXE): crypt.o $(LIBS)
	$(CC) $(LDFLAGS) -o $@ crypt.o libcrypt.a

$(STATICLIB): encrypt.o
	ar rv $@ encrypt.o

$(SHAREDLIB): encrypt.o
	$(CC) $(LDFLAGS) -shared -Wl,--out-implib=$(IMPORTLIB) -Wl,--export-all \
	$^ -o $@

encrypt.o: encrypt.c encrypt.h

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

