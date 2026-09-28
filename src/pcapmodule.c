#include "pcapmodule.h"

static PyModuleDef pcap_module = {
    PyModuleDef_HEAD_INIT,
    "pckt.pcap",
    "PCAP Python wrapper",
    -1,
    PyPCAP_module_methods
};

PyMODINIT_FUNC PyInit_pcap(void) {
    PyObject *mod;
    int ok;

    ok = PyType_Ready(&PyPCAP_Type);
    if(0 > ok) {
        return NULL;
    }

    mod = PyModule_Create(&pcap_module);
    if(NULL == mod) {
        return NULL;
    }

    Py_INCREF(&PyPCAP_Type);

    PyPCAP_Error = PyErr_NewException("pckt.pcap.error", NULL, NULL);
    Py_INCREF(PyPCAP_Error);
    PyModule_AddObject(mod, "error", PyPCAP_Error);

    PyModule_AddIntConstant(mod, "D_IN",    PCAP_D_IN   );
    PyModule_AddIntConstant(mod, "D_OUT",   PCAP_D_OUT  );
    PyModule_AddIntConstant(mod, "D_INOUT", PCAP_D_INOUT);
#ifdef PCAP_NETMASK_UNKNOWN
    PyModule_AddIntConstant(mod, "NETMASK_UNKNOWN", PCAP_NETMASK_UNKNOWN);
#endif

    return mod;
}

static PyObject * PyPCAP_lib_version(PyObject *self) {
    return Py_BuildValue("s", pcap_lib_version());
}

static PyObject * find_mac(char *ifname) {
    PyObject *macaddr = NULL;

#ifdef WIN32

    // TODO

#else

    struct ifreq ifr;
    int fd;

    memset(&ifr, 0, sizeof(struct ifreq));

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
    ifr.ifr_name[IFNAMSIZ-1] = 0;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(0 > fd) {
        return NULL;
    }

    if(0 == ioctl(fd, SIOCGIFHWADDR, &ifr)) {
        macaddr = PyBytes_FromStringAndSize((char *)ifr.ifr_hwaddr.sa_data, 6);
    }

#endif

    return macaddr;
}

static PyObject * PyPCAP_findalldevs(PyObject *self) {
    PyObject *devdict;
    PyObject *addrdict;
    PyObject *value;

    pcap_if_t *devices;
    pcap_if_t *current;
    pcap_addr_t *address;
    struct sockaddr *sa;
    struct sockaddr_in *sai;
    char errbuf[PCAP_ERRBUF_SIZE];

    // find all interfaces
    if(-1 == pcap_findalldevs(&devices, errbuf)) {
        PyErr_SetString(PyPCAP_Error, errbuf);
        return NULL;
    }

    devdict = PyDict_New();

    current = devices;
    while(current) {
        addrdict = PyDict_New();
        PyDict_SetItemString(devdict, current->name, addrdict);
        Py_DECREF(addrdict);

        value = find_mac(current->name);
        if(value) {
            PyDict_SetItemString(addrdict, "mac", value);
            Py_DECREF(value);
        }

        address = current->addresses;
        while(address) {
            sa = address->addr;
            switch(sa->sa_family) {
            case AF_INET:
                if(address->addr) {
                    sai = (struct sockaddr_in *)address->addr;
                    value = PyUnicode_FromString(inet_ntoa(sai->sin_addr));
                    PyDict_SetItemString(addrdict, "ip", value);
                    Py_DECREF(value);
                }

                if(address->netmask) {
                    sai = (struct sockaddr_in *)address->netmask;
                    value = PyUnicode_FromString(inet_ntoa(sai->sin_addr));
                    PyDict_SetItemString(addrdict, "netmask", value);
                    Py_DECREF(value);
                }

                if(address->broadaddr) {
                    sai = (struct sockaddr_in *)address->broadaddr;
                    value = PyUnicode_FromString(inet_ntoa(sai->sin_addr));
                    PyDict_SetItemString(addrdict, "broadcast", value);
                    Py_DECREF(value);
                }
                break;
            }

            // TODO: IPv6

            address = address->next;
        }

        current = current->next;
    }

    // Free the linked list
    pcap_freealldevs(devices);

    // Return the dictionary of devices
    return devdict;
}

static PyObject * PyPCAP_open_live(PyObject *self, PyObject *args) {
    PyPCAP *pypcap;
    const char *device;
    int snaplen = 65535;
    int promisc = 1;
    int to_ms = 0;

    if(!PyArg_ParseTuple(args, "s|iii", &device, &snaplen, &promisc, &to_ms)) {
        PyErr_SetString(PyPCAP_Error, "Invalid arguments, see __doc__");
        return NULL;
    }

    // allocate a pcap object
    pypcap = (PyPCAP *)PyObject_CallObject((PyObject *)&PyPCAP_Type, NULL);
    if(!pypcap) {
        PyErr_SetString(PyPCAP_Error, "Could not create a pcap handle");
        return NULL;
    }

    // open the device
    pypcap->pd = pcap_open_live(device, snaplen, promisc, to_ms, pypcap->errbuf);
    if(!pypcap->pd) {
        PyErr_SetString(PyPCAP_Error, pypcap->errbuf);
        Py_DECREF(pypcap);
        return NULL;
    }

    snprintf(pypcap->device, sizeof(pypcap->device), "%s", device);

#ifdef WIN32
    pcap_setmintocopy(pypcap->pd, 14);
#endif

    return (PyObject *)pypcap;
}

static PyObject * PyPCAP_open_offline(PyObject *self, PyObject *args) {
    PyPCAP *pypcap;
    const char *file;

    file = PyUnicode_AsUTF8(args);
    if(!file) {
        return NULL;
    }

    // allocate an event object
    pypcap = (PyPCAP *)PyObject_CallObject((PyObject *)&PyPCAP_Type, NULL);
    if(!pypcap) {
        PyErr_SetString(PyPCAP_Error, "Could not create a pcap handle");
        return NULL;
    }

    // open the device
    pypcap->pd = pcap_open_offline(file, pypcap->errbuf);
    if(!pypcap->pd) {
        PyErr_SetString(PyPCAP_Error, pypcap->errbuf);
        Py_DECREF(pypcap);
        return NULL;
    }

    return (PyObject *)pypcap;
}

#define TIMESTAMP(hdr) ((double)(hdr)->ts.tv_sec + (hdr)->ts.tv_usec / 1e6)

// runs inside pcap_loop(), which is called with the GIL released
static void pcap_callback(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data) {
    PyPCAP *self = (PyPCAP *)user;
    PyGILState_STATE gil;
    PyObject *head;
    PyObject *args = NULL;
    PyObject *retval = NULL;

    gil = PyGILState_Ensure();

    head = Py_BuildValue("(y#dk)", data, (Py_ssize_t)hdr->caplen, TIMESTAMP(hdr), (unsigned long)hdr->len);
    if(head) {
        args = PySequence_Concat(head, self->cbargs);
        Py_DECREF(head);
    }

    if(args) {
        retval = PyObject_CallObject(self->cb, args);
        Py_DECREF(args);
    }

    // an exception from the callback, or a pending signal (e.g. Ctrl-C), stops the loop
    if(!retval || 0 > PyErr_CheckSignals()) {
        pcap_breakloop(self->pd);
    }

    Py_XDECREF(retval);

    PyGILState_Release(gil);
}

////////////////////////////////////////////////////////////////////////////////

void PyPCAP_Type_dealloc(PyPCAP *self) {
    if(self->pd) {
        pcap_close(self->pd);
    }

    Py_CLEAR(self->cb);
    Py_CLEAR(self->cbargs);

    Py_TYPE(self)->tp_free((PyObject *)self);
}

PyObject * PyPCAP_Type_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
    PyPCAP *self;

    self = (PyPCAP *)type->tp_alloc(type, 0);
    if(self) {
        self->pd = NULL;
        self->cb = NULL;
        self->cbargs = NULL;
    }

    return (PyObject *)self;
}

int PyPCAP_Type_init(PyPCAP *self, PyObject *args, PyObject *kwds) {
    memset(self->device, 0, sizeof(self->device));
    return 0;
}

static PyObject * PyPCAP_list_datalinks(PyPCAP *self) {
    PyObject *links;
    PyObject *value;
    int *dlts;
    int len;
    int idx;

    PCAPCTX;

    len = pcap_list_datalinks(self->pd, &dlts);
    if(-1 == len) {
        PyErr_SetString(PyPCAP_Error, pcap_geterr(self->pd));
        return NULL;
    }

    links = PyList_New(len);

    for(idx = 0; idx < len; ++idx) {
        // name/description may be NULL for unknown DLTs; "s" maps NULL to None
        value = Py_BuildValue("iss", dlts[idx], pcap_datalink_val_to_name(dlts[idx]), pcap_datalink_val_to_description(dlts[idx]));
        if(!value) {
            pcap_free_datalinks(dlts);
            Py_DECREF(links);
            return NULL;
        }
        PyList_SET_ITEM(links, idx, value);
    }

    pcap_free_datalinks(dlts);

    return links;
}

static PyObject * PyPCAP_datalink(PyPCAP *self) {
    int dlt;

    PCAPCTX;

    dlt = pcap_datalink(self->pd);

    return Py_BuildValue("iss", dlt, pcap_datalink_val_to_name(dlt), pcap_datalink_val_to_description(dlt));
}

static PyObject * PyPCAP_setdirection(PyPCAP *self, PyObject *args) {
#ifndef WIN32
    pcap_direction_t dir;

    PCAPCTX;

    if(!PyArg_ParseTuple(args, "i", &dir)) {
        return NULL;
    }

    if(-1 == pcap_setdirection(self->pd, dir)) {
        PyErr_SetString(PyPCAP_Error, pcap_geterr(self->pd));
        return NULL;
    }
#endif
    Py_RETURN_NONE;
}

static PyObject * PyPCAP_setnonblock(PyPCAP *self, PyObject *args) {
    int nonblock;

    PCAPCTX;

    nonblock = PyObject_IsTrue(args);
    if(0 > nonblock) {
        return NULL;
    }

    if(PCAP_ERROR == pcap_setnonblock(self->pd, nonblock, self->errbuf)) {
        PyErr_SetString(PyPCAP_Error, self->errbuf);
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyObject * PyPCAP_getnonblock(PyPCAP *self) {
    int nonblock;

    PCAPCTX;

    nonblock = pcap_getnonblock(self->pd, self->errbuf);
    if(PCAP_ERROR == nonblock) {
        PyErr_SetString(PyPCAP_Error, self->errbuf);
        return NULL;
    }

    return PyBool_FromLong(nonblock);
}

static PyObject * PyPCAP_setfilter(PyPCAP *self, PyObject *args) {
    struct bpf_program bpf;
    bpf_u_int32 network;
    bpf_u_int32 netmask;
    const char *filter;

    PCAPCTX;

    filter = PyUnicode_AsUTF8(args);
    if(!filter) {
        return NULL;
    }

    if(0 > pcap_lookupnet(self->device, &network, &netmask, self->errbuf)) {
        netmask = 0xffffffff;
    }

    if(0 > pcap_compile(self->pd, &bpf, filter, 1, netmask)) {
        PyErr_SetString(PyPCAP_Error, pcap_geterr(self->pd));
        return NULL;
    }

    if(0 > pcap_setfilter(self->pd, &bpf)) {
        pcap_freecode(&bpf);
        PyErr_SetString(PyPCAP_Error, pcap_geterr(self->pd));
        return NULL;
    }

    pcap_freecode(&bpf);

    Py_RETURN_NONE;
}

static PyObject * PyPCAP_loop(PyPCAP *self, PyObject *args) {
    Py_ssize_t len;
    int cnt = -1;
    int retval;

    PCAPCTX;

    len = PyTuple_GET_SIZE(args);
    if(len == 0) {
        PyErr_SetString(PyPCAP_Error, "Invalid arguments, see __doc__");
        return NULL;
    }

    if(!PyCallable_Check(PyTuple_GET_ITEM(args, 0))) {
        PyErr_SetString(PyPCAP_Error, "Invalid callback");
        return NULL;
    }

    Py_CLEAR(self->cb);
    self->cb = PyTuple_GET_ITEM(args, 0);

    Py_INCREF(self->cb);

    if(1 < len) {
        cnt = PyLong_AsLong(PyTuple_GET_ITEM(args, 1));
        if(cnt == -1 && PyErr_Occurred()) {
            return NULL;
        }
    }

    Py_CLEAR(self->cbargs);
    self->cbargs = PyTuple_GetSlice(args, 2, len);

    Py_BEGIN_ALLOW_THREADS
    retval = pcap_loop(self->pd, cnt, pcap_callback, (u_char *)self);
    Py_END_ALLOW_THREADS

    // the callback breaks the loop when it raises, so its exception takes priority
    if(PCAP_ERROR == retval && !PyErr_Occurred()) {
        PyErr_SetString(PyPCAP_Error, pcap_geterr(self->pd));
    }

    if(PyErr_Occurred()) {
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyObject * PyPCAP_breakloop(PyPCAP *self) {
    PCAPCTX;

    pcap_breakloop(self->pd);

    Py_RETURN_NONE;
}

static PyObject * PyPCAP_next_ex(PyPCAP *self) {
    struct pcap_pkthdr *hdr;
    const u_char *data;
    int retval;

    PCAPCTX;

    Py_BEGIN_ALLOW_THREADS
    retval = pcap_next_ex(self->pd, &hdr, &data);
    Py_END_ALLOW_THREADS

    if(1 == retval) {
        return Py_BuildValue("(y#dk)", data, (Py_ssize_t)hdr->caplen, TIMESTAMP(hdr), (unsigned long)hdr->len);
    }
    else if(0 == retval || PCAP_ERROR_BREAK == retval) {
        // timeout, or no more packets in a file
        Py_RETURN_NONE;
    }
    else {
        PyErr_SetString(PyPCAP_Error, pcap_geterr(self->pd));
        return NULL;
    }
}

#ifndef WIN32
static PyObject * PyPCAP_inject(PyPCAP *self, PyObject *args) {
    char *data;
    Py_ssize_t len;
    int sent;

    PCAPCTX;

    if(-1 == PyBytes_AsStringAndSize(args, &data, &len)) {
        return NULL;
    }

    sent = pcap_inject(self->pd, data, len);
    if(-1 == sent) {
        PyErr_SetString(PyPCAP_Error, pcap_geterr(self->pd));
        return NULL;
    }

    return Py_BuildValue("i", sent);
}
#endif

static PyObject * PyPCAP_sendpacket(PyPCAP *self, PyObject *args) {
    char *data;
    Py_ssize_t len;

    PCAPCTX;

    if(-1 == PyBytes_AsStringAndSize(args, &data, &len)) {
        return NULL;
    }

    if(-1 == pcap_sendpacket(self->pd, (const u_char *)data, (int)len)) {
        PyErr_SetString(PyPCAP_Error, pcap_geterr(self->pd));
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyObject * PyPCAP_snapshot(PyPCAP *self) {
    PCAPCTX;

    return Py_BuildValue("i", pcap_snapshot(self->pd));
}

static PyObject * PyPCAP_close(PyPCAP *self) {
    if(self->pd) {
        pcap_close(self->pd);
        self->pd = NULL;
    }

    Py_RETURN_NONE;
}

static PyObject * PyPCAP_stats(PyPCAP *self) {
    struct pcap_stat ps;

    PCAPCTX;

    if(-1 == pcap_stats(self->pd, &ps)) {
        PyErr_SetString(PyPCAP_Error, pcap_geterr(self->pd));
        return NULL;
    }

    return Py_BuildValue("III", ps.ps_recv, ps.ps_drop, ps.ps_ifdrop);
}


/*
int pcap_compile(pcap_t *p, struct bpf_program *fp, const char *str, int optimize, bpf_u_int32 netmask);
int pcap_dispatch(pcap_t *p, int cnt, pcap_handler callback, u_char *user);
*/

#include "win32.c"
