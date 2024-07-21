/* Compile with: gcc find_device.c -lpcap */

#include "main.h"

int main(int argc, char **argv)
{
    char *device;                        /* Name of device (e.g. eth0, wlan0) */
    char error_buffer[PCAP_ERRBUF_SIZE]; /* Size defined in pcap.h */
    if (GetInterfaceName(argc, device, argv, error_buffer))
    {
        return 1;
    }
    std::cout << "Network device found: " << device << std::endl;

    pcap_t *handle;

    handle = pcap_open_live(device, BUFSIZ, 1, 1000, error_buffer);
    if (handle == NULL) 
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, error_buffer);
        return 2;
    }

    if (pcap_datalink(handle) != DLT_EN10MB)
    {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", device);
        return 2;
    }

    char filter_exp[] = "ether dst 47:00:00:00:00:00 and ether src 12:00:00:00:00:00 and ether[12:2] >= 0x2e and ether[12:2] <= 1500";
    if (SetFilter(handle, filter_exp))
    {
        return 2;
    }

    struct pcap_pkthdr header;
    const u_char *packet;

    packet = pcap_next(handle, &header);
    frame_capture_handler(nullptr, &header, packet);
    std::cout << "End of prog" << std::endl;

    enum PCAP_CONST_t {
        INFINITE_FRAME_POLLING = -1
    };
    pcap_loop(handle, INFINITE_FRAME_POLLING, frame_capture_handler, nullptr);

    pcap_close(handle);
    return 0;
}

int SetFilter(pcap_t *handle, char *filter_exp)
{
    struct bpf_program fp;

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }
    return 0;
}

bool GetInterfaceName(int argc, char *&device, char **argv, char error_buffer[PCAP_ERRBUF_SIZE])
{
    if (argc > 1)
    {
        device = argv[1];
        std::cout << "Device: " << device << std::endl;
    }
    else
    {
        pcap_if_t *all_devices;
        if (pcap_findalldevs(&all_devices, error_buffer))
        {
            std::cerr << "Error finding device: " << error_buffer << std::endl;
            return true;
        }
        if (all_devices->next == NULL)
        {
            device = all_devices->name;
        }
        else
        {
            pcap_if_t *all_devices_temp = all_devices;
            uint32_t device_counter = 1;
            std::cout << "Was found next interfaces:\n"
                      << device_counter << ")\t" << all_devices_temp->name << "\n";
            while (all_devices_temp->next != NULL)
            {
                all_devices_temp = all_devices_temp->next;
                std::cout << ++device_counter << ")\t" << all_devices_temp->name << "\n";
            }
            std::cout << "Choose one." << std::endl;
            uint64_t choice_value = 0;
            while (!(std::cin >> choice_value) || choice_value == 0 || choice_value > device_counter)
            {
                std::cin.clear();
                std::cin.ignore(100, '\n');
                std::cout << "Invalid input. Choose another one." << std::endl;
            }
            for (size_t i = 1; i < choice_value; ++i)
            {
                all_devices = all_devices->next;
            }
            device = all_devices->name;
        }
    }
    return false;
}

void frame_capture_handler(u_char *nothing, const struct pcap_pkthdr *header, const u_char *packet)
{
    std::cout << "Captured a packet with length of " << header->len << "\n";
    std::cout << "Capture length: " << header->caplen << "\n";
    std::cout << "Capture time: " << header->ts.tv_sec << " sec, " << header->ts.tv_usec << " usec" << std::endl;

    const struct sniff_ethernet *ethernet = (struct sniff_ethernet *)(packet);
    const char *payload = (char *)(packet + SIZE_ETHERNET);

    std::cout << std::hex;
    std::cout << "Destination MAC address: ";
    for (size_t i = 0; i < ETHER_ADDR_LEN; i++)
    {
        std::cout << std::setw(2) << std::setfill('0') << static_cast<uint32_t>(ethernet->ether_dhost[i]) << ((i != ETHER_ADDR_LEN - 1) ? ":" : "");
    }
    std::cout << "\nSource MAC address: ";
    for (size_t i = 0; i < ETHER_ADDR_LEN; i++)
    {
        std::cout << std::setw(2) << std::setfill('0') << static_cast<uint32_t>(ethernet->ether_shost[i]) << ((i != ETHER_ADDR_LEN - 1) ? ":" : "");
    }
    std::cout << "\nType/Length field: " << ntohs(ethernet->ether_type) << "\nPayload: ";

    for (size_t i = 0; i < header->len - SIZE_ETHERNET; i++)
    {
        std::cout << static_cast<uint32_t>(*(payload + i)) << " ";
    }
    std::cout << std::endl;
    std::cout << std::dec;

    // TODO: Add logic for checking packet contents
    bool valid_packet = true;

    // Check MAC addresses
    uint8_t expected_dst_mac[ETHER_ADDR_LEN] = {0x47, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t expected_src_mac[ETHER_ADDR_LEN] = {0x12, 0x00, 0x00, 0x00, 0x00, 0x00};
    for (size_t i = 0; i < ETHER_ADDR_LEN; i++)
    {
        if (ethernet->ether_dhost[i] != expected_dst_mac[i] || ethernet->ether_shost[i] != expected_src_mac[i])
        {
            valid_packet = false;
            break;
        }
    }

    // Check payload length
    if (header->len < SIZE_ETHERNET + 46)
    {
        valid_packet = false;
    }

    // Check payload content (example check)
    for (size_t i = 0; i < header->len - SIZE_ETHERNET; i++)
    {
        if (*(payload + i) != i)
        {
            valid_packet = false;
            break;
        }
    }

    if (valid_packet)
    {
        std::cout << "Packet is valid.\n";
    }
    else
    {
        std::cout << "Packet is invalid.\n";
    }
}
