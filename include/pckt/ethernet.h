#ifndef __ETHERNET_H__
#define __ETHERNET_H__

#define ETHERNET_ADDR_LEN 6

#define ETHERNET_IP   0x0800
#define ETHERNET_ARP  0x0806
#define ETHERNET_RARP 0x8035

#define ETHERNET_HDR_LEN sizeof(struct Ethernet)

struct Ethernet {
    uint8_t  dst[ETHERNET_ADDR_LEN];
    uint8_t  src[ETHERNET_ADDR_LEN];
    uint16_t type;
};

#endif // __ETHERNET_H__
