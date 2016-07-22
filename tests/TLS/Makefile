all: tls notls

tls:
	gcc -m32 -g -ggdb -pthread -o test-tls test-tls.c

notls:
	gcc -m32 -g -ggdb -pthread -o test-notls test-notls.c

clean:
	rm test-tls
	rm test-notls
