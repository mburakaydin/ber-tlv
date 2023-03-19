CC=gcc
CFLAGS=-I. -fPIC
DEPS = ber-tlv.h
OBJ = ber-tlv.o
TESTOBJ = ber-tlv.o tests/tests.o
LIBNAME=libber-tlv.so


%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

lib:	$(OBJ) 
	$(CC) -shared -o $(LIBNAME) -fPIC $(OBJ)
	
all:	lib test

clean:
	rm -rf *.o *.so

test: $(TESTOBJ)
	$(CC) -o $@ $^ $(CFLAGS) -L tests -lunity
