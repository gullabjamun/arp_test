pcap_test: main.o printfunc.o
	gcc -o pcap_test main.o printfunc.o -lpcap

printfunc.o: printfunc.c
	gcc -c -o printfunc.o printfunc.c -lpcap

main.o: main.c
	gcc -c -o main.o main.c -lpcap

clean:
	rm *.o pcap_test

