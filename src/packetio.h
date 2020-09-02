#ifndef __PACKETIO_H__
#define __PACKETIO_H__

#include <Python.h>
#include <structmember.h>

#include <packetio/ethernet.h>
#include <packetio/ip.h>
#include <packetio/arp.h>
#include <packetio/tcp.h>
#include <packetio/udp.h>
#include <packetio/icmp.h>

#define  DOC_MOD  "PacketIO"

extern PyTypeObject PacketIO_Ethernet_Type;
extern PyTypeObject PacketIO_ARP_Type;
extern PyTypeObject PacketIO_IP_Type;
extern PyTypeObject PacketIO_TCP_Type;
extern PyTypeObject PacketIO_UDP_Type;
extern PyTypeObject PacketIO_ICMP_Type;


typedef struct {
    PyObject_HEAD
    Ethernet ethernet;
    PyObject *layer3;
} PacketIO_Ethernet;

typedef struct {
    PyObject_HEAD
    ARP arp;
} PacketIO_ARP;

typedef struct {
    PyObject_HEAD
    IP ip;
    // TODO: ip header options
    PyObject *layer4;
} PacketIO_IP;

typedef struct {
    PyObject_HEAD
    TCP tcp;
    PyObject *data;
} PacketIO_TCP;

typedef struct {
    PyObject_HEAD
    UDP udp;
    PyObject *data;
} PacketIO_UDP;

typedef struct {
    PyObject_HEAD
    ICMP icmp;
    PyObject *data;
} PacketIO_ICMP;


#endif // __PACKETIO_H__
