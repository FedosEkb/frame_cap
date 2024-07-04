#ifndef MAIN_H
#define MAIN_H
#include <stdio.h>
#include <pcap.h>
#include <iostream>
#include <string>


/* MAC addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Заголовки Ethernet всегда состоят из 14 байтов */
#define SIZE_ETHERNET 14

bool GetInterfaceName(int argc, char *&device, char **argv, char error_buffer[PCAP_ERRBUF_SIZE]);

int SetFilter(pcap_t *handle, char* filter_exp);

void frame_capture_handler(u_char *nothing, const struct pcap_pkthdr *header, const u_char *packet);

/* Заголовок Ethernet */
struct sniff_ethernet
{
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Адрес назначения */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Адрес источника */
    u_short ether_type;                 /* IP? ARP? RARP? и т.д. */
};

#endif /* MAIN_H */
