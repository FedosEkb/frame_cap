#ifndef MAIN_H
#define MAIN_H
#include <stdio.h>
#include <pcap.h>
#include <iostream>
#include <string>

/* MAC addresses are 6 bytes */
#define ETHER_ADDR_LEN 6

/* Заголовки Ethernet всегда состоят из 14 байтов */
#define SIZE_ETHERNET 14

bool GetInterfaceName(int argc, char *&device, char **argv, char error_buffer[PCAP_ERRBUF_SIZE]);

int SetFilter(pcap_t *handle, char *filter_exp);

void frame_capture_handler(u_char *nothing, const struct pcap_pkthdr *header, const u_char *packet);

/* Заголовок Ethernet */
struct sniff_ethernet
{
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Адрес назначения */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Адрес источника */
    u_short ether_type;                 /* IP? ARP? RARP? и т.д. */
};

//! \brief Типы пакетов при обменах с имитаторами СТИ и ИВВС.
enum user_packet_type_t : uint16_t
{
    STI_FRAME = 0x0001,                   //!< Кадр ЦТМИ.
    PERIPHERAL_DEVICES_SETTINGS = 0x0002, //!< Передача настроек ПП в СТИ.
    IVVS_OUTPUTS_SETTINGS = 0x0003,       //!< Настройки выходов ИВВС.
    POWER_SUPPLY_COMMANDS = 0x0004,       //!< Команды управления ИП СТИ и ИП СУ СВ.
    IVVS_INPUTS_REQUEST = 0x0005,         //!< Запрос состояния входов регистрации релейных команд.
    IVVS_INPUTS_STATE = 0x0006            //!< Передача состояния входов регистрации релейных команд.
};

//! \brief диапазон измерений канала
enum MEASURE_RANGE_t : uint8_t
{
    FROM_NEG_50_TO_50 = 0b11110000,
    FROM_0_TO_100 = 0b00001111
};

//! \brief Настройки канала преобразования тока прибора ПрТН.
struct current_channel_settings
{
    MEASURE_RANGE_t range; //!< Настройка параметра.
    uint8_t div;           //!< Коэффициент деления ДЕП.
};

//! \brief Настройки прибора ПрТН.

#pragma pack(push, 1) // NOTE если этого не сделать между uint8_t SCh и channel_settings T[5] окажется пустой байт
struct prtn_settings
{
    current_channel_settings T[5]; //!< Каналы для преобразования токов.
    uint8_t div_U[10];             //!< Коэффициент деления ДЕП для напряжения.
    uint8_t div_Uk_0;              //!< Коэффициент деления ДЕП для нижней границы преобразования.
    uint8_t div_Uk_100;            //!< Коэффициент деления ДЕП для верхней границы преобразования.
};
#pragma pack(pop)

//! \brief Настройки прибора ПрТ.
struct prt_settings
{
    uint8_t div_current; //!< Коэффициент деления ДЕП для тока.
    uint8_t div_Uk_0;    //!< Коэффициент деления ДЕП для нижней границы преобразования.
    uint8_t div_Uk_100;  //!< Коэффициент деления ДЕП для верхней границы преобразования.
};

//! \brief Номер луча ВААР.
enum VAAR_RAY_NUMBER_t : uint8_t
{
    RAY_0 = 0x00,
    RAY_1 = 0xE1,
    RAY_2 = 0xD2,
    RAY_3 = 0xC3,
    RAY_4 = 0xB4,
    RAY_5 = 0xA5,
    RAY_6 = 0x96,
    RAY_7 = 0x87,
    RAY_8 = 0x78,
    RAY_9 = 0x69
};

//! \brief Установка сухих контактов с 1 по 8.
union contacts1_8_t
{
    uint8_t clear_all;
    struct number
    {
        uint8_t first : 1;
        uint8_t second : 1;
        uint8_t three : 1;
        uint8_t four : 1;
        uint8_t five : 1;
        uint8_t six : 1;
        uint8_t seven : 1;
        uint8_t eight : 1;
    } number;
};

//! \brief Установка сухих контактов с 9 по 12.
union contact9_12_t
{
    uint8_t clear_all;
    struct number
    {
        uint8_t nine : 1;
        uint8_t ten : 1;
        uint8_t eleven : 1;
        uint8_t twelve : 1;
    } number;
};

//! \brief Установка шин питания с 1 по 7.
union buses1_7_t
{
    uint8_t clear_all;
    struct number
    {
        uint8_t first : 1;
        uint8_t second : 1;
        uint8_t three : 1;
        uint8_t four : 1;
        uint8_t five : 1;
        uint8_t six : 1;
        uint8_t seven : 1;
    } number;
};

//! \brief Установка источников питания СТИ.
union power_supply_sti_t
{
    uint8_t clear_all;
    struct number
    {
        uint8_t first : 1;
        uint8_t reserve : 3;
        uint8_t second : 1;
    } number;
};

//! \brief Настройки прибора ПрКИР.
struct prkir_settings
{
    VAAR_RAY_NUMBER_t ray_number;        //!< Номер луча.
    contacts1_8_t contacts1_8;           //!< Сухой контакт №1-8.
    contact9_12_t contacts9_12;          //!< Сухой контакт №9-12.
    buses1_7_t buses1_7;                 //!< Шины №1-7.
    power_supply_sti_t sti_power_supply; //!< Источник питания СТИ.
};

//! \brief Кадр ЦТМИ для задачи Основная работа.
struct __attribute__((packed)) sti_frame_t
{
    uint16_t packet_type;    //!< Тип пакета.
    uint32_t cycle_number;   //!< Номер цикла.
    uint16_t err_counter;    //!< Счетчик сбоев РСУ ТИ.
    uint8_t err_count;       //!< Счётчик сбоев сети.
    uint8_t block;           //!< Признак блокировки сети.
    uint8_t conf_valid;      //!< Корректна ли последняя заданная конфигурация.
    uint8_t device_valid[3]; //!< Признаки исправности ПП1...ПП3.
    uint64_t update_time;    //!< Время последнего обновления данных синхронизации.
    uint8_t data[1204];      //!< Данные, полученные от ПрТН, ПрТ, ПрКИР.

    //! \brief Конструктор структуры.
    sti_frame_t() : packet_type(STI_FRAME),
                    cycle_number(0),
                    err_counter(0),
                    err_count(0),
                    block(0),
                    conf_valid(0),
                    device_valid{0},
                    update_time(0) {}
};

//! \brief Пакет с настройками ПП для вывода в СТИ.
struct __attribute__((packed)) devices_settings_frame_t
{
    uint16_t packet_type;      //!< Тип пакета.
    uint32_t cycle_number;     //!< Номер цикла.
    uint16_t synch_period;     //!< Период синхронизации.
    prtn_settings prtn_data;   //!< Настройки ПрТН.
    prt_settings prt_data;     //!< Настройки ПрТ.
    prkir_settings prkir_data; //!< Настройки ПрКИР.

    //! \brief Конструктор структуры.
    devices_settings_frame_t() : packet_type(PERIPHERAL_DEVICES_SETTINGS),
                                 cycle_number(0),
                                 synch_period(0) {}
};

#endif /* MAIN_H */
