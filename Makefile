arp_test: main.o printfunc.o
	gcc -w -Wall -o arp_test main.o printfunc.o -lpcap

printfunc.o: printfunc.c
	gcc -w -Wall -c -o printfunc.o printfunc.c -lpcap

main.o: main.c
	gcc -w -Wall -c -o main.o main.c -lpcap

clean:
	rm *.o arp_test

