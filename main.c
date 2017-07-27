#include <pcap.h>
#include "protocol_information.h"
#include "printfunc.h"
    #include <stdio.h>
#include <arpa/inet.h>
#define ETHERTYPE_IP 0x0800

     int main(int argc, char *argv[])
     {
	u_char send_packet[42];
	u_char receive_packet[42];


        pcap_t *handle;			/* Session handle */
        char *dev;			/* The device to sniff on */
        char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
        struct bpf_program fp;		/* The compiled filter */
        char filter_exp[] = "port 80";	/* The filter expression */
        bpf_u_int32 mask;		/* Our netmask */
        bpf_u_int32 net;		/* Our IP */
        struct pcap_pkthdr *header;	/* The header that pcap gives us */
        const u_char *packet;		/* The actual packet */

	u_short datalength;
	u_char tcpoff;
	u_char ipoff;
	char ip_dst_str[16];
	char ip_src_str[16];
	struct arphdr *arprequest;
	struct arphdr *arpreply;
	struct sniff_ethernet *ethernet;
	struct sniff_ip *ip;
	struct sniff_tcp *tcp;
	struct sniff_data *data;

	u_char sender_ip_str[4];
	u_char target_ip_str[4];

	u_char *sender_ip=argv[2];
	u_char *target_ip=argv[3];

        /* Define the device */
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
            return(2);
        }
        /* Find the properties for the device */
        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
            fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
            net = 0;
            mask = 0;
        }
        /* Open the session in promiscuous mode */
        handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
            return(2);
        }
        /* Compile and apply the filter */
        if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
            return(2);
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
            return(2);
        }

	while(1)
	{
		inet_pton(AF_INET,sender_ip,(*arprequest).spa);
		inet_pton(AF_INET,target_ip,(*arprequest).spa);
	      	printf("%s\n",sender_ip);
		printf("%s\n",target_ip);
	      	printf("%2x\n",*((*arprequest).spa));
		printf("%2x\n",*((*arprequest).spa));
	}

        pcap_close(handle);
        return(0);
     }
