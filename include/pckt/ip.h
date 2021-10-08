#ifndef __IP_H__
#define __IP_H__

#define IP_ICMP 0x01
#define IP_IGMP 0x02
#define IP_TCP  0x06
#define IP_UDP  0x11

#define IP_HDR_LEN sizeof(struct IP)

struct IP {
#ifdef LITTLE_ENDIAN
    uint8_t  hlen:4;
    uint8_t  vers:4;
#elif BIG_ENDIAN
    uint8_t  vers:4;
    uint8_t  hlen:4;
#endif // ENDIAN
    uint8_t  tos;
    uint16_t len;
    uint16_t id;
    uint16_t frag;
    uint8_t  ttl;
    uint8_t  proto;
    uint16_t crc;
    uint32_t src;
    uint32_t dst;
};

#endif // __IP_H__
