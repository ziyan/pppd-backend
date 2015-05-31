all: backend.so pybackend.so

backend.so: backend.c
	$(CC) -Wall -o $@ -shared -fPIC $^

pybackend.so: pybackend.c
	$(CC) -Wall -o $@ -shared -fPIC $^ -lpython2.7

install: backend.so pybackend.so
	install -o root -g root -m 0644 backend.so /usr/lib*/pppd/*/
	install -o root -g root -m 0644 pybackend.so /usr/lib*/pppd/*/

clean:
	rm -f *.o *.so *.a *~

