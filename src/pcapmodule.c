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

// fills mac[6] with the interface's hardware address; returns -1 with errno set on failure
static int find_mac(const char *ifname, unsigned char *mac) {
#if defined(WIN32)

    errno = ENOSYS;
    return -1;

#elif defined(__APPLE__)

    int mib[6];
    size_t len;
    char *buf;
    struct sockaddr_dl *sdl;

    mib[0] = CTL_NET;
    mib[1] = AF_ROUTE;
    mib[2] = 0;
    mib[3] = AF_LINK;
    mib[4] = NET_RT_IFLIST;
    mib[5] = if_nametoindex(ifname);
    if(0 == mib[5]) {
        return -1;
    }

    if(0 > sysctl(mib, 6, NULL, &len, NULL, 0)) {
        return -1;
    }

    buf = malloc(len);
    if(!buf) {
        return -1;
    }

    if(0 > sysctl(mib, 6, buf, &len, NULL, 0)) {
        free(buf);
        return -1;
    }

    // the interface's link-level address follows its if_msghdr
    sdl = (struct sockaddr_dl *)((struct if_msghdr *)buf + 1);
    if(6 != sdl->sdl_alen) {
        free(buf);
        errno = EADDRNOTAVAIL;
        return -1;
    }

    memcpy(mac, LLADDR(sdl), 6);
    free(buf);

    // macOS hides the address from processes that aren't root and reports this one instead
    if(0 == memcmp(mac, "\x02\x00\x00\x00\x00\x00", 6)) {
        errno = EPERM;
        return -1;
    }

    return 0;

#else

    struct ifreq ifr;
    int fd;
    int ok;
    int err;

    memset(&ifr, 0, sizeof(struct ifreq));

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
    ifr.ifr_name[IFNAMSIZ-1] = 0;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(0 > fd) {
        return -1;
    }

    ok = ioctl(fd, SIOCGIFHWADDR, &ifr);
    err = errno;
    close(fd);

    if(0 > ok) {
        errno = err;
        return -1;
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    return 0;

#endif
}

static PyObject * PyPCAP_mac(PyObject *self, PyObject *args) {
    const char *ifname;
    unsigned char mac[6];

    ifname = PyUnicode_AsUTF8(args);
    if(!ifname) {
        return NULL;
    }

    if(0 > find_mac(ifname, mac)) {
        PyErr_Format(PyPCAP_Error, "%s: %s", ifname, strerror(errno));
        return NULL;
    }

    return PyBytes_FromStringAndSize((char *)mac, 6);
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
    unsigned char mac[6];
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

        if(0 == find_mac(current->name, mac)) {
            value = PyBytes_FromStringAndSize((char *)mac, 6);
            PyDict_SetItemString(addrdict, "mac", value);
            Py_DECREF(value);
        }

#ifdef WIN32
        // the connection name ("Ethernet"), which open_live() and create() also accept
        if(0 == strncmp(current->name, NPF_PREFIX, strlen(NPF_PREFIX))) {
            value = device_to_canonical(current->name + strlen(NPF_PREFIX));
            if(value) {
                PyDict_SetItemString(addrdict, "name", value);
                Py_DECREF(value);
            }
        }
#endif

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

#ifdef WIN32
    char npf[MAX_PATH];
#endif

    if(!PyArg_ParseTuple(args, "s|iii", &device, &snaplen, &promisc, &to_ms)) {
        PyErr_SetString(PyPCAP_Error, "Invalid arguments, see __doc__");
        return NULL;
    }

#ifdef WIN32
    if(0 == canonical_to_device(device, npf)) {
        device = npf;
    }
#endif

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

static PyObject * PyPCAP_create(PyObject *self, PyObject *args) {
    PyPCAP *pypcap;
    const char *device;

#ifdef WIN32
    char npf[MAX_PATH];
#endif

    device = PyUnicode_AsUTF8(args);
    if(!device) {
        return NULL;
    }

#ifdef WIN32
    if(0 == canonical_to_device(device, npf)) {
        device = npf;
    }
#endif

    pypcap = (PyPCAP *)PyObject_CallObject((PyObject *)&PyPCAP_Type, NULL);
    if(!pypcap) {
        PyErr_SetString(PyPCAP_Error, "Could not create a pcap handle");
        return NULL;
    }

    // unlike pcap_open_live(), an unknown device isn't reported until activate()
    pypcap->pd = pcap_create(device, pypcap->errbuf);
    if(!pypcap->pd) {
        PyErr_SetString(PyPCAP_Error, pypcap->errbuf);
        Py_DECREF(pypcap);
        return NULL;
    }

    snprintf(pypcap->device, sizeof(pypcap->device), "%s", device);

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

// the message for a pcap_activate() status; some only say what went wrong in pcap_geterr()
static const char * activate_message(PyPCAP *self, int status) {
    switch(status) {
    case PCAP_WARNING:
    case PCAP_ERROR:
    case PCAP_ERROR_NO_SUCH_DEVICE:
    case PCAP_ERROR_PERM_DENIED:
#ifdef PCAP_ERROR_CAPTURE_NOTSUP
    case PCAP_ERROR_CAPTURE_NOTSUP:
#endif
        if(*pcap_geterr(self->pd)) {
            return pcap_geterr(self->pd);
        }
    }

    return pcap_statustostr(status);
}

static PyObject * PyPCAP_activate(PyPCAP *self) {
    int status;

    PCAPCTX;

    status = pcap_activate(self->pd);
    if(0 > status) {
        PyErr_Format(PyPCAP_Error, "%s: %s", self->device, activate_message(self, status));
        return NULL;
    }
    else if(0 < status) {
        return PyUnicode_FromString(activate_message(self, status));
    }

    Py_RETURN_NONE;
}

// the pcap_set_*() calls fail with PCAP_ERROR_ACTIVATED once the handle is active
static PyObject * set_result(int status) {
    if(0 > status) {
        PyErr_SetString(PyPCAP_Error, pcap_statustostr(status));
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyObject * PyPCAP_set_snaplen(PyPCAP *self, PyObject *args) {
    long snaplen;

    PCAPCTX;

    snaplen = PyLong_AsLong(args);
    if(-1 == snaplen && PyErr_Occurred()) {
        return NULL;
    }

    return set_result(pcap_set_snaplen(self->pd, (int)snaplen));
}

static PyObject * PyPCAP_set_promisc(PyPCAP *self, PyObject *args) {
    int promisc;

    PCAPCTX;

    promisc = PyObject_IsTrue(args);
    if(0 > promisc) {
        return NULL;
    }

    return set_result(pcap_set_promisc(self->pd, promisc));
}

static PyObject * PyPCAP_set_timeout(PyPCAP *self, PyObject *args) {
    long to_ms;

    PCAPCTX;

    to_ms = PyLong_AsLong(args);
    if(-1 == to_ms && PyErr_Occurred()) {
        return NULL;
    }

    return set_result(pcap_set_timeout(self->pd, (int)to_ms));
}

static PyObject * PyPCAP_set_immediate_mode(PyPCAP *self, PyObject *args) {
    int immediate;

    PCAPCTX;

    immediate = PyObject_IsTrue(args);
    if(0 > immediate) {
        return NULL;
    }

    return set_result(pcap_set_immediate_mode(self->pd, immediate));
}

static PyObject * PyPCAP_geterr(PyPCAP *self) {
    PCAPCTX;

    return PyUnicode_FromString(pcap_geterr(self->pd));
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
    if(0 > dlt) {
        PyErr_SetString(PyPCAP_Error, pcap_statustostr(dlt));
        return NULL;
    }

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
    else if(0 == retval) {
        // timeout, or nothing available in non-blocking mode
        Py_RETURN_NONE;
    }
    else if(PCAP_ERROR_BREAK == retval) {
        PyErr_SetNone(PyExc_EOFError);
        return NULL;
    }
    else {
        PyErr_SetString(PyPCAP_Error, pcap_geterr(self->pd));
        return NULL;
    }
}

#ifndef WIN32
static PyObject * PyPCAP_fileno(PyPCAP *self) {
    int fd;

    PCAPCTX;

    fd = pcap_get_selectable_fd(self->pd);
    if(-1 == fd) {
        PyErr_SetString(PyPCAP_Error, "no selectable descriptor for this handle");
        return NULL;
    }

    return PyLong_FromLong(fd);
}

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
    int snaplen;

    PCAPCTX;

    snaplen = pcap_snapshot(self->pd);
    if(0 > snaplen) {
        PyErr_SetString(PyPCAP_Error, pcap_statustostr(snaplen));
        return NULL;
    }

    return Py_BuildValue("i", snaplen);
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
