#ifndef __ARP_H__
#define __ARP_H__

#define ARP_HW_ADDR_LEN 6
#define ARP_PROTO_ADDR_LEN 4

#define ARP_ETH  0x0001
#define ARP_IP   0x0800

#define ARP_REQ  0x0001
#define ARP_REP  0x0002
#define RARP_REQ 0x0003
#define RARP_REP 0x0004

#define ARP_HDR_LEN sizeof(struct ARP)

struct ARP {
    uint16_t  hw;
    uint16_t  proto;
    uint8_t   hwsize;
    uint8_t   protosize;
    uint16_t  op;
    uint8_t   src_mac[ARP_HW_ADDR_LEN];
    uint8_t   src_ip[ARP_PROTO_ADDR_LEN];
    uint8_t   dst_mac[ARP_HW_ADDR_LEN];
    uint8_t   dst_ip[ARP_PROTO_ADDR_LEN];
};

#endif // __ARP_H__
