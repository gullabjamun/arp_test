arp_test: main.o printfunc.o
	gcc -o arp_test main.o printfunc.o -lpcap

printfunc.o: printfunc.c
	gcc -c -o printfunc.o printfunc.c -lpcap

main.o: main.c
	gcc -c -o main.o main.c -lpcap

clean:
	rm *.o arp_test

