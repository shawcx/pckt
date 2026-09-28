#ifndef __UDP_H__
#define __UDP_H__

#include <stdint.h>

#define UDP_HDR_LEN sizeof(struct UDP)

struct UDP
{
	uint16_t src;
	uint16_t dst;
	uint16_t len;
	uint16_t crc;
};

typedef struct UDP UDP;

#endif // __UDP_H__

