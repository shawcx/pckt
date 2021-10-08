#ifndef __UDP_H__
#define __UDP_H__

#define UDP_HDR_LEN sizeof(struct UDP)

struct UDP {
    uint16_t src;
    uint16_t dst;
    uint16_t len;
    uint16_t crc;
};

#endif // __UDP_H__
