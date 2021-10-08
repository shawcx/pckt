#ifndef __TCP_H__
#define __TCP_H__

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

#define TCP_HDR_LEN sizeof(struct TCP)

struct TCP {
    uint16_t src;
    uint16_t dst;
    uint32_t seq;
    uint32_t ack;
#ifdef LITTLE_ENDIAN
    uint8_t  null:4;
    uint8_t  hlen:4;
#elif BIG_ENDIAN
    uint8_t  hlen:4;
    uint8_t  null:4;
#endif // ENDIAN
    uint8_t  flags;
    uint16_t window;
    uint16_t crc;
    uint16_t urgent;
};

#endif // __TCP_H__
