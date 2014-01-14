PREFIX=/usr

# MAKEFILE for GCC
CFLAGS = -O2 -Wall -c -I./ -Werror -Wall
CC=$(CROSS_PREFIX)gcc
LD=$(CROSS_PREFIX)ld
AR=$(CROSS_PREFIX)ar

#x86 optimizations
CFLAGS += -fomit-frame-pointer -funroll-loops

default:libcrypt.a
all: libcrypt.a

libcrypt.a: base64.o rsa_sys.o rsa.o yarrow.o ctr.o cbc.o hash.o tiger.o sha1.o md5.o sha256.o serpent.o safer+.o rc6.o rc5.o blowfish.o crypt.o mpi.o prime.o
	$(AR) rs libcrypt.a base64.o rsa_sys.o rsa.o yarrow.o ctr.o cbc.o hash.o tiger.o sha1.o md5.o sha256.o serpent.o safer+.o rc6.o rc5.o blowfish.o crypt.o mpi.o prime.o

test.exe: libcrypt.a test.o
	$(CC) test.o libcrypt.a -o test.exe

clean:
	rm -f *.a *.o *.exe *.log *.aux *.dvi *.toc *.idx *.ilg

install: libcrypt.a
	install -d $(DESTDIR)$(PREFIX)/include  $(DESTDIR)$(PREFIX)/lib
	install -m 0644 *.h $(DESTDIR)$(PREFIX)/include
	install -m 0644 libcrypt.a $(DESTDIR)$(PREFIX)/lib
