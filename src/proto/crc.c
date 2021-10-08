
DWORD _psuedo_crc(BYTE *pkt) {
    WORD *words = (WORD *)pkt;
    DWORD crc;

    // calculate length of the packet without the ip header
    crc = ntohs(words[1]) - ((pkt[0] & 0x0f) << 2);

    // add the protocol byte
    crc += pkt[9];

    // add the src and dst as words
    crc += ntohs(words[6]);
    crc += ntohs(words[7]);
    crc += ntohs(words[8]);
    crc += ntohs(words[9]);

    return crc;
}

void _ip_crc(BYTE *pkt) {
    WORD *words = (WORD *)pkt;
    DWORD crc = 0;
    int len;

    // set the CRC to zero
    words[5] = 0;

    // calculate the number of words
    len = ((pkt[0] & 0x0f) << 1);
    while(len--) {
        crc += ntohs(words[len]);
    }

    while(crc & 0xffff0000)
        crc = (crc >> 16) + (crc & 0xffff);

    words[5] = (WORD)htons((WORD)~crc);
}

void _icmp_crc(BYTE *pkt) {
    WORD *words = (WORD *)pkt;
    DWORD crc = 0;
    int hlen;
    int len;

    // length of the header and the packet
    hlen = (pkt[0] & 0x0f) << 2;
    len = ntohs(words[1]);

    // start of the TCP header
    words = (WORD *)(pkt + hlen);

    // set the CRC to zero
    words[1] = 0;

    // padding for odd number of bytes
    if(1 & len) {
        crc += ntohs(pkt[len - 1]);
    }

    // calculate the number of words
    len = (len - hlen) >> 1;
    while(len--) {
        crc += ntohs(words[len]);
    }

    while(crc & 0xffff0000)
        crc = (crc >> 16) + (crc & 0xffff);

    words[1] = (WORD)htons((WORD)~crc);
}

void _tcp_crc(BYTE *pkt) {
    WORD *words = (WORD *)pkt;
    DWORD crc;
    int hlen;
    int len;

    crc = _psuedo_crc(pkt);

    // length of the header and the packet
    hlen = (pkt[0] & 0x0f) << 2;
    len = ntohs(words[1]);

    // start of the TCP header
    words = (WORD *)(pkt + hlen);

    // set the CRC to zero
    words[8] = 0;

    // padding for odd number of bytes
    if(1 & len) {
        crc += ntohs(pkt[len - 1]);
    }

    // calculate the number of WORDs
    len = (len - hlen) >> 1;
    while(len--) {
        crc += ntohs(words[len]);
    }

    while(crc & 0xffff0000)
        crc = (crc >> 16) + (crc & 0xffff);

    words[8] = (WORD)htons((WORD)~crc);
}

void _udp_crc(BYTE *pkt) {
    WORD *words = (WORD *)pkt;
    DWORD crc;
    int hlen;
    int len;

    crc = _psuedo_crc(pkt);

    // length of the header and the packet
    hlen = (pkt[0] & 0x0f) << 2;
    len = ntohs(words[1]);

    // start of the UDP header
    words = (WORD *)(pkt + hlen);

    // set the CRC to zero
    words[3] = 0;

    if(1 & len) {
        crc += ntohs(pkt[len - 1]);
    }

    // calculate the number of WORDs
    len = (len - hlen) >> 1;
    while(len--) {
        crc += ntohs(words[len]);
    }

    while(crc & 0xffff0000)
        crc = (crc >> 16) + (crc & 0xffff);

    words[3] = (WORD)htons((WORD)~crc);
}

void crc(BYTE *pkt) {
    switch(pkt[9]) {
    case 1:
        _icmp_crc(pkt);
        break;
    case 6:
        _tcp_crc(pkt);
        break;
    case 17:
        _udp_crc(pkt);
        break;
    }

    _ip_crc(pkt);
}

