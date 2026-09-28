#include "packetio.h"

static PyObject * PacketIO_unpack ( PyObject *, PyObject * );

//static PyMethodDef PacketIO_methods[] = {
//    { "unpack", (PyCFunction)PacketIO_unpack, METH_O },
//    { NULL }
//};

static PyModuleDef packetio_module = {
    PyModuleDef_HEAD_INIT,
    "packetio",
    DOC_MOD,
    -1,
    NULL //PacketIO_methods
};

PyMODINIT_FUNC PyInit_packetio(void) {
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

    Py_INCREF(&PacketIO_Ethernet_Type);
    PyModule_AddObject(mod, "ethernet", (PyObject *)&PacketIO_Ethernet_Type);

    Py_INCREF(&PacketIO_ARP_Type);
    PyModule_AddObject(mod, "arp", (PyObject *)&PacketIO_ARP_Type);

    Py_INCREF(&PacketIO_IP_Type);
    PyModule_AddObject(mod, "ip", (PyObject *)&PacketIO_IP_Type);

    Py_INCREF(&PacketIO_TCP_Type);
    PyModule_AddObject(mod, "tcp", (PyObject *)&PacketIO_TCP_Type);

    Py_INCREF(&PacketIO_UDP_Type);
    PyModule_AddObject(mod, "udp", (PyObject *)&PacketIO_UDP_Type);

    Py_INCREF(&PacketIO_ICMP_Type);
    PyModule_AddObject(mod, "icmp", (PyObject *)&PacketIO_ICMP_Type);

    PyModule_AddIntMacro(mod, ETHERNET_ADDR_LEN);
    PyModule_AddIntMacro(mod, ETHERNET_IP);
    PyModule_AddIntMacro(mod, ETHERNET_ARP);
    PyModule_AddIntMacro(mod, ETHERNET_RARP);
    PyModule_AddIntMacro(mod, ETHERNET_HDR_LEN);

    PyModule_AddIntMacro(mod, ARP_ETH);
    PyModule_AddIntMacro(mod, ARP_IP);
    PyModule_AddIntMacro(mod, ARP_REQ);
    PyModule_AddIntMacro(mod, ARP_REP);
    PyModule_AddIntMacro(mod, RARP_REQ);
    PyModule_AddIntMacro(mod, RARP_REP);
    PyModule_AddIntMacro(mod, ARP_HDR_LEN);

    PyModule_AddIntMacro(mod, IP_ICMP);
    PyModule_AddIntMacro(mod, IP_IGMP);
    PyModule_AddIntMacro(mod, IP_TCP);
    PyModule_AddIntMacro(mod, IP_UDP);
    PyModule_AddIntMacro(mod, IP_HDR_LEN);

    PyModule_AddIntMacro(mod, TCP_FIN);
    PyModule_AddIntMacro(mod, TCP_SYN);
    PyModule_AddIntMacro(mod, TCP_RST);
    PyModule_AddIntMacro(mod, TCP_PSH);
    PyModule_AddIntMacro(mod, TCP_ACK);
    PyModule_AddIntMacro(mod, TCP_URG);
    PyModule_AddIntMacro(mod, TCP_HDR_LEN);

    PyModule_AddIntMacro(mod, UDP_HDR_LEN);

    PyModule_AddIntMacro(mod, ICMP_ECHOREPLY);
    PyModule_AddIntMacro(mod, ICMP_DEST_UNREACH);
    PyModule_AddIntMacro(mod, ICMP_SOURCE_QUENCH);
    PyModule_AddIntMacro(mod, ICMP_REDIRECT);
    PyModule_AddIntMacro(mod, ICMP_ECHO);
    PyModule_AddIntMacro(mod, ICMP_ROUTERADVERT);
    PyModule_AddIntMacro(mod, ICMP_ROUTERSOLICIT);
    PyModule_AddIntMacro(mod, ICMP_TIME_EXCEEDED);
    PyModule_AddIntMacro(mod, ICMP_PARAMETERPROB);
    PyModule_AddIntMacro(mod, ICMP_TIMESTAMP);
    PyModule_AddIntMacro(mod, ICMP_TIMESTAMPREPLY);
    PyModule_AddIntMacro(mod, ICMP_INFO_REQUEST);
    PyModule_AddIntMacro(mod, ICMP_INFO_REPLY);
    PyModule_AddIntMacro(mod, ICMP_ADDRESS);
    PyModule_AddIntMacro(mod, ICMP_ADDRESSREPLY);
    PyModule_AddIntMacro(mod, ICMP_NET_UNREACH);
    PyModule_AddIntMacro(mod, ICMP_HOST_UNREACH);
    PyModule_AddIntMacro(mod, ICMP_PROT_UNREACH);
    PyModule_AddIntMacro(mod, ICMP_PORT_UNREACH);
    PyModule_AddIntMacro(mod, ICMP_FRAG_NEEDED);
    PyModule_AddIntMacro(mod, ICMP_SR_FAILED);
    PyModule_AddIntMacro(mod, ICMP_NET_UNKNOWN);
    PyModule_AddIntMacro(mod, ICMP_HOST_UNKNOWN);
    PyModule_AddIntMacro(mod, ICMP_HOST_ISOLATED);
    PyModule_AddIntMacro(mod, ICMP_NET_ANO);
    PyModule_AddIntMacro(mod, ICMP_HOST_ANO);
    PyModule_AddIntMacro(mod, ICMP_NET_UNR_TOS);
    PyModule_AddIntMacro(mod, ICMP_HOST_UNR_TOS);
    PyModule_AddIntMacro(mod, ICMP_PKT_FILTERED);
    PyModule_AddIntMacro(mod, ICMP_PREC_VIOLATION);
    PyModule_AddIntMacro(mod, ICMP_PREC_CUTOFF);
    PyModule_AddIntMacro(mod, ICMP_REDIR_NET);
    PyModule_AddIntMacro(mod, ICMP_REDIR_HOST);
    PyModule_AddIntMacro(mod, ICMP_REDIR_NETTOS);
    PyModule_AddIntMacro(mod, ICMP_REDIR_HOSTTOS);
    PyModule_AddIntMacro(mod, ICMP_EXC_TTL);
    PyModule_AddIntMacro(mod, ICMP_EXC_FRAGTIME);
    PyModule_AddIntMacro(mod, ICMP_HDR_LEN);

    return mod;
}

//static PyObject * PacketIO_unpack(PyObject *self, PyObject *args) {
//    Py_RETURN_NONE;
//}
