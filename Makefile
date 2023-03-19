CC=gcc
CFLAGS=-I. -fPIC
DEPS = ber-tlv.h
OBJ = ber-tlv.o
TESTOBJ = ber-tlv.o tests/tests.o tests/unity.o
LIBNAME=libber-tlv.so


%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

all:	lib test

lib:	$(OBJ) 
	$(CC) -shared -o $(LIBNAME) -fPIC $(OBJ)
	
clean:
	rm -rf *.o *.so

test: $(TESTOBJ)
	$(CC) -o $@ $^ $(CFLAGS) 
