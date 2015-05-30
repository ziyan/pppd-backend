
all: backend.so pybackend.so

backend.so: backend.c
	$(CC) -Wall -o $@ -shared -fPIC $^

pybackend.so: pybackend.c
	$(CC) -Wall -o $@ -shared -fPIC $^ -lpython2.7

clean:
	rm -f *.o *.so *.a *~

