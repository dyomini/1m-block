all: 1m-block

1m-block: main.c
	gcc -O2 -o 1m-block main.c -lnetfilter_queue -lrt

clean:
	rm -f 1m-block