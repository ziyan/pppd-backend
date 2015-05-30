
all: backend.so

%.so: %.c
	$(CC) -Wall -o $@ -shared -fPIC $^

clean:
	rm -f *.o *.so *.a *~

