all: netfilter-test

netfilter-test: main.c
	gcc -o netfilter-test main.c -lnetfilter_queue

clean:
	rm -f netfilter-test