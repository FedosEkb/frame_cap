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
    return 0;

    char filter_exp[] = "ether dst 47:00:00:00:00:00 and ether src 12:00:00:00:00:00"; /* Выражение фильтра */

    if (SetFilter(handle, filter_exp))
    {
        return 2;
    }
}

/// @brief Устанавливает фильтр на 
/// @param handle 
/// @param filter_exp 
/// @return 
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
            std::cout << "Error finding device: " << error_buffer << std::endl;
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