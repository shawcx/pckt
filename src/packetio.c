#include "packetio.h"

static PyObject * PacketIO_unpack ( PyObject *, PyObject * );

//static PyMethodDef PacketIO_methods[] = {
//    { "unpack", (PyCFunction)PacketIO_unpack, METH_O },
//    { NULL }
//};

static PyModuleDef packetio_module = {
    PyModuleDef_HEAD_INIT,
    DOC_MOD,
    NULL,
    -1,
    NULL //PacketIO_methods
};

PyMODINIT_FUNC PyInit__packetio(void) {
    PyObject *parent;
    PyObject *mod;
    int ok;

    ok = PyType_Ready(&PacketIO_Ethernet_Type);
    if(0 > ok) {
        return NULL;
    }

    ok = PyType_Ready(&PacketIO_ARP_Type);
    if(0 > ok) {
        return NULL;
    }

    ok = PyType_Ready(&PacketIO_IP_Type);
    if(0 > ok) {
        return NULL;
    }

    ok = PyType_Ready(&PacketIO_TCP_Type);
    if(0 > ok) {
        return NULL;
    }

    ok = PyType_Ready(&PacketIO_UDP_Type);
    if(0 > ok) {
        return NULL;
    }

    ok = PyType_Ready(&PacketIO_ICMP_Type);
    if(0 > ok) {
        return NULL;
    }

    mod = PyModule_Create(&packetio_module);
    if(NULL == mod) {
        return NULL;
    }

    parent = PyImport_ImportModule("packetio");

    Py_INCREF(&PacketIO_Ethernet_Type);
    PyModule_AddObject(parent, "ethernet", (PyObject *)&PacketIO_Ethernet_Type);

    Py_INCREF(&PacketIO_ARP_Type);
    PyModule_AddObject(parent, "arp", (PyObject *)&PacketIO_ARP_Type);

    Py_INCREF(&PacketIO_IP_Type);
    PyModule_AddObject(parent, "ip", (PyObject *)&PacketIO_IP_Type);

    Py_INCREF(&PacketIO_TCP_Type);
    PyModule_AddObject(parent, "udp", (PyObject *)&PacketIO_UDP_Type);

    Py_INCREF(&PacketIO_UDP_Type);
    PyModule_AddObject(parent, "udp", (PyObject *)&PacketIO_UDP_Type);

    Py_INCREF(&PacketIO_ICMP_Type);
    PyModule_AddObject(parent, "icmp", (PyObject *)&PacketIO_ICMP_Type);

    PyModule_AddIntMacro(parent, ETHERNET_ADDR_LEN);
    PyModule_AddIntMacro(parent, ETHERNET_IP);
    PyModule_AddIntMacro(parent, ETHERNET_ARP);
    PyModule_AddIntMacro(parent, ETHERNET_RARP);
    PyModule_AddIntMacro(parent, ETHERNET_HDR_LEN);

    PyModule_AddIntMacro(parent, ARP_ETH);
    PyModule_AddIntMacro(parent, ARP_IP);
    PyModule_AddIntMacro(parent, ARP_REQ);
    PyModule_AddIntMacro(parent, ARP_REP);
    PyModule_AddIntMacro(parent, RARP_REQ);
    PyModule_AddIntMacro(parent, RARP_REP);
    PyModule_AddIntMacro(parent, ARP_HDR_LEN);

    PyModule_AddIntMacro(parent, IP_ICMP);
    PyModule_AddIntMacro(parent, IP_IGMP);
    PyModule_AddIntMacro(parent, IP_TCP);
    PyModule_AddIntMacro(parent, IP_UDP);
    PyModule_AddIntMacro(parent, IP_HDR_LEN);

    PyModule_AddIntMacro(parent, TCP_FIN);
    PyModule_AddIntMacro(parent, TCP_SYN);
    PyModule_AddIntMacro(parent, TCP_RST);
    PyModule_AddIntMacro(parent, TCP_PSH);
    PyModule_AddIntMacro(parent, TCP_ACK);
    PyModule_AddIntMacro(parent, TCP_URG);
    PyModule_AddIntMacro(parent, TCP_HDR_LEN);

    PyModule_AddIntMacro(parent, UDP_HDR_LEN);

    PyModule_AddIntMacro(parent, ICMP_ECHOREPLY);
    PyModule_AddIntMacro(parent, ICMP_DEST_UNREACH);
    PyModule_AddIntMacro(parent, ICMP_SOURCE_QUENCH);
    PyModule_AddIntMacro(parent, ICMP_REDIRECT);
    PyModule_AddIntMacro(parent, ICMP_ECHO);
    PyModule_AddIntMacro(parent, ICMP_ROUTERADVERT);
    PyModule_AddIntMacro(parent, ICMP_ROUTERSOLICIT);
    PyModule_AddIntMacro(parent, ICMP_TIME_EXCEEDED);
    PyModule_AddIntMacro(parent, ICMP_PARAMETERPROB);
    PyModule_AddIntMacro(parent, ICMP_TIMESTAMP);
    PyModule_AddIntMacro(parent, ICMP_TIMESTAMPREPLY);
    PyModule_AddIntMacro(parent, ICMP_INFO_REQUEST);
    PyModule_AddIntMacro(parent, ICMP_INFO_REPLY);
    PyModule_AddIntMacro(parent, ICMP_ADDRESS);
    PyModule_AddIntMacro(parent, ICMP_ADDRESSREPLY);
    PyModule_AddIntMacro(parent, ICMP_NET_UNREACH);
    PyModule_AddIntMacro(parent, ICMP_HOST_UNREACH);
    PyModule_AddIntMacro(parent, ICMP_PROT_UNREACH);
    PyModule_AddIntMacro(parent, ICMP_PORT_UNREACH);
    PyModule_AddIntMacro(parent, ICMP_FRAG_NEEDED);
    PyModule_AddIntMacro(parent, ICMP_SR_FAILED);
    PyModule_AddIntMacro(parent, ICMP_NET_UNKNOWN);
    PyModule_AddIntMacro(parent, ICMP_HOST_UNKNOWN);
    PyModule_AddIntMacro(parent, ICMP_HOST_ISOLATED);
    PyModule_AddIntMacro(parent, ICMP_NET_ANO);
    PyModule_AddIntMacro(parent, ICMP_HOST_ANO);
    PyModule_AddIntMacro(parent, ICMP_NET_UNR_TOS);
    PyModule_AddIntMacro(parent, ICMP_HOST_UNR_TOS);
    PyModule_AddIntMacro(parent, ICMP_PKT_FILTERED);
    PyModule_AddIntMacro(parent, ICMP_PREC_VIOLATION);
    PyModule_AddIntMacro(parent, ICMP_PREC_CUTOFF);
    PyModule_AddIntMacro(parent, ICMP_REDIR_NET);
    PyModule_AddIntMacro(parent, ICMP_REDIR_HOST);
    PyModule_AddIntMacro(parent, ICMP_REDIR_NETTOS);
    PyModule_AddIntMacro(parent, ICMP_REDIR_HOSTTOS);
    PyModule_AddIntMacro(parent, ICMP_EXC_TTL);
    PyModule_AddIntMacro(parent, ICMP_EXC_FRAGTIME);
    PyModule_AddIntMacro(parent, ICMP_HDR_LEN);

    Py_DECREF(parent);

    return mod;
}

//static PyObject * PacketIO_unpack(PyObject *self, PyObject *args) {
//    Py_RETURN_NONE;
//}
