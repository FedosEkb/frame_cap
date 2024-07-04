/* Compile with: gcc find_device.c -lpcap */

#include "main.h"

int main(int argc, char **argv)
{
    char *device;                        /* Name of device (e.g. eth0, wlan0) */
    char error_buffer[PCAP_ERRBUF_SIZE]; /* Size defined in pcap.h */
    if (GetInterfaceName(argc, device, argv,error_buffer))
    {
        return 1;
    }
    std::cout << "Network device found: " << device << std::endl;

    pcap_t *handle;

    handle = pcap_open_live(device, BUFSIZ, 1, 1000, error_buffer);
    // NOTE BUFSIZ -  максимальное число байт принетое с нитерфейса
    // NOTE 1 - promisc mode
    // NOTE 1000 - это время чтения в миллисекундах

    if (handle == NULL) 
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, error_buffer);
        return(2);
    }

    if (pcap_datalink(handle) != DLT_EN10MB)  // NOTE удостоверимся, что мы получаем кадры c Ethernet заголовками, 
    {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers -not supported\n", device);
        return (2);
    }
    
    char filter_exp[] = "ether dst 47:00:00:00:00:00 and ether src 12:00:00:00:00:00"; /* Выражение фильтра */

    if (SetFilter(handle, filter_exp))
    {
        return 2;
    }

    struct pcap_pkthdr header; /* Заголовок который нам дает PCAP */
    const u_char *packet;  /* Пакет */

     /* Захват пакета */
    packet = pcap_next(handle, &header);
    frame_capture_handler(nullptr, &header, packet);
    std::cout << "end of prog"<< std::endl;
enum PCAP_CONST_t{
    INFINITE_FRAME_POLLING = -1
};
    pcap_loop(handle,INFINITE_FRAME_POLLING,frame_capture_handler,nullptr); // NOTE this is infinite call!!

    /* Закрытие сессии */
    pcap_close(handle);
    return 0;
}

/// @brief Устанавливает фильтр на соединение
/// @param handle Хендлер сокета продостовляемый PCAP
/// @param filter_exp Фильтр навешиваемый на сокет
/// @return Статус операции.
int SetFilter(pcap_t *handle, char *filter_exp)
{
    struct bpf_program fp; /* Скомпилированный фильтр */

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return (2);
    }

    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return (2);
    }
    return 0;
}

/// @brief Выбора интерфейса логирования
/// @param argc первый параметр main
/// @param device указатель который будет установлен на имя выбраного интерфейса
/// @param argv первый параметр main
/// @return 
bool GetInterfaceName(int argc, char *&device, char **argv,char error_buffer[PCAP_ERRBUF_SIZE])
{
    if (argc > 1)
    {
        device = argv[1];
        std::cout << "Device :" << device << std::endl;
    }
    else
    {
        /* Find a device */
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
            std::cout << "Choice one." << std::endl;
            uint64_t choice_value = 0;
            std::string temp;
            while (!(std::cin >> choice_value) || choice_value == 0 || choice_value > device_counter)
            {
                std::cin.clear();
                std::cin.ignore(100, '\n');
                std::cout << "Invalid input. Choice another one." << std::endl;
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

/// @brief Функция "обработки" 
/// @param nothing параметр не ипстользуется, добавлен для совметимости с сингнатурой pcap_loop
/// @param header Pointer to generic per-packet information, supplied by libpcap.
/// @param packet Pointer to packet address.
void frame_capture_handler(u_char *nothing, const struct pcap_pkthdr *header, const u_char *packet)
{
    std::cout << "Jacked a packet with length of " << header->len << "\n";
    std::cout << "Jacked a packet with capture length of " << header->caplen << "\n";
    std::cout << "Capture time is " << header->ts.tv_sec << " sec, " << header->ts.tv_usec << " usec" << std::endl;
    const struct sniff_ethernet *ethernet; /* Заголовок Ethernet */
    const char *payload;                   /* Данные пакета */

    ethernet = (struct sniff_ethernet *)(packet);

    payload = (char *)(packet + SIZE_ETHERNET);

    std::cout << std::hex;
    std::cout << "dest MAC addr: ";
    for (size_t i = 0; i < ETHER_ADDR_LEN; i++)
    {
        std::cout << static_cast<uint32_t>(ethernet->ether_dhost[i]) << ((i != ETHER_ADDR_LEN - 1) ? ":" : "");
    }
    std::cout << "\n"
              << "src MAC addr: ";
    for (size_t i = 0; i < ETHER_ADDR_LEN; i++)
    {
        std::cout << static_cast<uint32_t>(ethernet->ether_shost[i]) << ((i != ETHER_ADDR_LEN - 1) ? ":" : "");
    }
    std::cout << "\n"
              << "type/len field: " << ntohs(ethernet->ether_type) << "\nbody of packet: ";
    for (size_t i = 0; i < header->len - SIZE_ETHERNET; i++)
    {
        std::cout << static_cast<uint32_t>(*(payload + i)) << " ";
    }
    std::cout << std::endl;
    std::cout << std::dec;
    // TODO  запихнуть сюда логику проверки!!
}