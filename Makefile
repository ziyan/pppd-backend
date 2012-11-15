
all: backend.so

%.so: %.c
	$(CC) -o $@ -shared -fPIC $^

#VERSION = $(shell awk -F '"' '/VERSION/ { print $$2; }' ../patchlevel.h)

clean:
	rm -f *.o *.so *.a *~

