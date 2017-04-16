CC = gcc
CFLAGS = -std=c11 -shared -fPIC -ldl
TARG = hw2.so

all: libinject.c
	$(CC) $< -o $(TARG) $(CFLAGS)

clean:
	rm $(TARG)
