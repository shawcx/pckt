#ifndef __PACKETIO_H__
#define __PACKETIO_H__

#include <Python.h>
#include <structmember.h>

#ifdef WIN32
 #include <winsock2.h>
#else
 // also defines the byte order macros used by the ip/tcp header bitfields
 #include <arpa/inet.h>
#endif

#include <pckt/ethernet.h>
#include <pckt/ip.h>
#include <pckt/arp.h>
#include <pckt/tcp.h>
#include <pckt/udp.h>
#include <pckt/icmp.h>

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
