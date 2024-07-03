#ifndef MAIN_H
#define MAIN_H
#include <stdio.h>
#include <pcap.h>
#include <iostream>
#include <string>

bool GetInterfaceName(int argc, char *&device, char **argv, char error_buffer[PCAP_ERRBUF_SIZE]);

int SetFilter(pcap_t *handle, char* filter_exp);

#endif /* MAIN_H */
