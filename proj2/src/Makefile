CC = gcc
CFLAGS = -w -std=c11 -shared -fPIC -ldl
TARG = hw2.so

all: libinject.c
	$(CC) $< -o $(TARG) $(CFLAGS)

extra: TestForExtra.c
	$(CC) $< -o extra.out

clean:
	rm $(TARG)
