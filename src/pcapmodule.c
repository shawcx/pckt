#include "pcapmodule.h"

#define BUSYCHECK if(self->busy) { PyErr_SetString(PyPCAP_Error, "handle is busy in loop(), dispatch() or next()"); return NULL; }

static PyModuleDef pcap_module = {
    PyModuleDef_HEAD_INIT,
    "pckt.pcap",
    "PCAP Python wrapper",
    -1,
    PyPCAP_module_methods
};

static const struct { const char *name; int value; } constants[] = {
    { "D_IN",    PCAP_D_IN    },
    { "D_OUT",   PCAP_D_OUT   },
    { "D_INOUT", PCAP_D_INOUT },
#ifdef PCAP_NETMASK_UNKNOWN
    { "NETMASK_UNKNOWN", (int)PCAP_NETMASK_UNKNOWN },
#endif

    // findalldevs() flags
    { "IF_LOOPBACK",                         PCAP_IF_LOOPBACK                         },
    { "IF_UP",                               PCAP_IF_UP                               },
    { "IF_RUNNING",                          PCAP_IF_RUNNING                          },
    { "IF_WIRELESS",                         PCAP_IF_WIRELESS                         },
    { "IF_CONNECTION_STATUS",                PCAP_IF_CONNECTION_STATUS                },
    { "IF_CONNECTION_STATUS_UNKNOWN",        PCAP_IF_CONNECTION_STATUS_UNKNOWN        },
    { "IF_CONNECTION_STATUS_CONNECTED",      PCAP_IF_CONNECTION_STATUS_CONNECTED      },
    { "IF_CONNECTION_STATUS_DISCONNECTED",   PCAP_IF_CONNECTION_STATUS_DISCONNECTED   },
    { "IF_CONNECTION_STATUS_NOT_APPLICABLE", PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE },

    // timestamp precisions and sources
    { "TSTAMP_PRECISION_MICRO",  PCAP_TSTAMP_PRECISION_MICRO  },
    { "TSTAMP_PRECISION_NANO",   PCAP_TSTAMP_PRECISION_NANO   },
    { "TSTAMP_HOST",             PCAP_TSTAMP_HOST             },
    { "TSTAMP_HOST_LOWPREC",     PCAP_TSTAMP_HOST_LOWPREC     },
    { "TSTAMP_HOST_HIPREC",      PCAP_TSTAMP_HOST_HIPREC      },
    { "TSTAMP_ADAPTER",          PCAP_TSTAMP_ADAPTER          },
    { "TSTAMP_ADAPTER_UNSYNCED", PCAP_TSTAMP_ADAPTER_UNSYNCED },
#ifdef PCAP_TSTAMP_HOST_HIPREC_UNSYNCED
    { "TSTAMP_HOST_HIPREC_UNSYNCED", PCAP_TSTAMP_HOST_HIPREC_UNSYNCED },
#endif

#ifdef WIN32
    // Npcap: setmode(), remote sources and sampling
    { "MODE_CAPT",                   MODE_CAPT                        },
    { "MODE_STAT",                   MODE_STAT                        },
    { "SRC_FILE",                    PCAP_SRC_FILE                    },
    { "SRC_IFLOCAL",                 PCAP_SRC_IFLOCAL                 },
    { "SRC_IFREMOTE",                PCAP_SRC_IFREMOTE                },
    { "OPENFLAG_PROMISCUOUS",        PCAP_OPENFLAG_PROMISCUOUS        },
    { "OPENFLAG_DATATX_UDP",         PCAP_OPENFLAG_DATATX_UDP         },
    { "OPENFLAG_NOCAPTURE_RPCAP",    PCAP_OPENFLAG_NOCAPTURE_RPCAP    },
    { "OPENFLAG_NOCAPTURE_LOCAL",    PCAP_OPENFLAG_NOCAPTURE_LOCAL    },
    { "OPENFLAG_MAX_RESPONSIVENESS", PCAP_OPENFLAG_MAX_RESPONSIVENESS },
    { "SAMP_NOSAMP",                 PCAP_SAMP_NOSAMP                 },
    { "SAMP_1_EVERY_N",              PCAP_SAMP_1_EVERY_N              },
    { "SAMP_FIRST_AFTER_N_MS",       PCAP_SAMP_FIRST_AFTER_N_MS       },
#endif // WIN32
};

PyMODINIT_FUNC PyInit_pcap(void) {
    PyObject *mod;
    size_t idx;

    PyTypeObject *types[] = { &PyPCAP_Type, &PyPacketIter_Type, &PyBPF_Type, &PyDumper_Type,
#ifdef WIN32
        &PySendQueue_Type,
#endif
    };

#ifdef PCAP_CHAR_ENC_UTF_8
    // libpcap 1.10+: take and return UTF-8 strings. Only Windows changes,
    // where libpcap otherwise uses the local code page.
    char errbuf[PCAP_ERRBUF_SIZE];

    if(0 > pcap_init(PCAP_CHAR_ENC_UTF_8, errbuf)) {
        PyErr_SetString(PyExc_ImportError, errbuf);
        return NULL;
    }
#endif

    for(idx = 0; idx < sizeof(types) / sizeof(types[0]); ++idx) {
        if(0 > PyType_Ready(types[idx])) {
            return NULL;
        }
    }

    mod = PyModule_Create(&pcap_module);
    if(NULL == mod) {
        return NULL;
    }

    // the types, for isinstance() and type hints, named after the last part of tp_name
    for(idx = 0; idx < sizeof(types) / sizeof(types[0]); ++idx) {
        if(0 > PyModule_AddType(mod, types[idx])) {
            goto error;
        }
    }

    PyPCAP_Error = PyErr_NewException("pckt.pcap.error", NULL, NULL);
    if(0 > PyModule_AddObjectRef(mod, "error", PyPCAP_Error)) {
        goto error;
    }

    for(idx = 0; idx < sizeof(constants) / sizeof(constants[0]); ++idx) {
        if(0 > PyModule_AddIntConstant(mod, constants[idx].name, constants[idx].value)) {
            goto error;
        }
    }

    return mod;

error:
    Py_DECREF(mod);
    return NULL;
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

// a str, or None for NULL
static PyObject * str_or_none(const char *text) {
    if(NULL == text) {
        Py_RETURN_NONE;
    }

    return PyUnicode_FromString(text);
}

// dict[key] = value, taking over the reference to value; -1 if either failed
static int set_new(PyObject *dict, const char *key, PyObject *value) {
    int ok;

    if(!value) {
        return -1;
    }

    ok = PyDict_SetItemString(dict, key, value);
    Py_DECREF(value);
    return ok;
}

// the text form of an IPv4 or IPv6 address, read as the given family (a
// netmask's own sa_family isn't always set), or None. BSDs trim trailing zero
// bytes from netmasks, so sa_len can be 5 for 255.0.0.0; libpcap copies them
// at the address's size, so the bytes past sa_len are whatever followed in
// getifaddrs()'s buffer. Copy only sa_len bytes into zeroed storage so those
// bytes count as zero.
static PyObject * address_string(int family, const struct sockaddr *sa) {
    struct sockaddr_storage copy;
    char text[INET6_ADDRSTRLEN];
    const void *addr;

    if(NULL == sa) {
        Py_RETURN_NONE;
    }

    memset(&copy, 0, sizeof(copy));
#ifdef SIN6_LEN
    memcpy(&copy, sa, sa->sa_len < sizeof(copy) ? sa->sa_len : sizeof(copy));
#else
    memcpy(&copy, sa, AF_INET6 == family ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in));
#endif

    if(AF_INET6 == family) {
        addr = &((struct sockaddr_in6 *)&copy)->sin6_addr;
    }
    else {
        addr = &((struct sockaddr_in *)&copy)->sin_addr;
    }

    if(NULL == inet_ntop(family, addr, text, sizeof(text))) {
        Py_RETURN_NONE;
    }

    return PyUnicode_FromString(text);
}

// appends value to the list under key in info, creating the list
static int append_address(PyObject *info, const char *key, PyObject *value) {
    PyObject *addrlist;

    addrlist = PyDict_GetItemString(info, key);
    if(!addrlist) {
        addrlist = PyList_New(0);
        if(0 > set_new(info, key, addrlist)) {
            return -1;
        }
    }

    return PyList_Append(addrlist, value);
}

// {'description', 'flags', 'addresses': [{'family', 'addr', 'netmask',
// 'broadcast', 'dstaddr'}, ...]}, with every IPv4 and IPv6 address listed
// again under 'ipv4' and 'ipv6', and the first IPv4 address's as 'ip',
// 'netmask' and 'broadcast'
static PyObject * describe_device(pcap_if_t *device) {
    static const char *flat[][2] = { { "addr", "ip" }, { "netmask", "netmask" }, { "broadcast", "broadcast" } };
    PyObject *info;
    PyObject *addresses = NULL;
    PyObject *entry = NULL;
    PyObject *value;
    pcap_addr_t *address;
    int family;
    int idx;

    info = PyDict_New();
    if(!info) {
        return NULL;
    }

    addresses = PyList_New(0);
    if(!addresses
        || 0 > set_new(info, "description", str_or_none(device->description))
        || 0 > set_new(info, "flags", PyLong_FromUnsignedLong(device->flags))
        || 0 > PyDict_SetItemString(info, "addresses", addresses)) {
        goto error;
    }

    for(address = device->addresses; address; address = address->next) {
        if(!address->addr) {
            continue;
        }

        family = address->addr->sa_family;
        if(AF_INET != family && AF_INET6 != family) {
            continue;
        }

        entry = Py_BuildValue("{s:i,s:N,s:N,s:N,s:N}",
            "family",    family,
            "addr",      address_string(family, address->addr),
            "netmask",   address_string(family, address->netmask),
            "broadcast", address_string(family, address->broadaddr),
            "dstaddr",   address_string(family, address->dstaddr));
        if(!entry || 0 > PyList_Append(addresses, entry)) {
            goto error;
        }

        value = PyDict_GetItemString(entry, "addr");
        if(Py_None != value && 0 > append_address(info, AF_INET == family ? "ipv4" : "ipv6", value)) {
            goto error;
        }

        // ip, netmask and broadcast are the first address's
        if(AF_INET == family && !PyDict_GetItemString(info, "ip")) {
            for(idx = 0; idx < 3; ++idx) {
                value = PyDict_GetItemString(entry, flat[idx][0]);
                if(Py_None != value && 0 > PyDict_SetItemString(info, flat[idx][1], value)) {
                    goto error;
                }
            }
        }

        Py_CLEAR(entry);
    }

    Py_DECREF(addresses);
    return info;

error:
    Py_XDECREF(entry);
    Py_XDECREF(addresses);
    Py_DECREF(info);
    return NULL;
}

static PyObject * PyPCAP_findalldevs(PyObject *self) {
    PyObject *devdict;
    PyObject *info;
    pcap_if_t *devices;
    pcap_if_t *current;
    unsigned char mac[6];
    char errbuf[PCAP_ERRBUF_SIZE];

    // find all interfaces
    if(-1 == pcap_findalldevs(&devices, errbuf)) {
        PyErr_SetString(PyPCAP_Error, errbuf);
        return NULL;
    }

    devdict = PyDict_New();
    if(!devdict) {
        goto error;
    }

    for(current = devices; current; current = current->next) {
        info = describe_device(current);
        if(0 > set_new(devdict, current->name, info)) {
            goto error;
        }

        if(0 == find_mac(current->name, mac)
            && 0 > set_new(info, "mac", PyBytes_FromStringAndSize((char *)mac, 6))) {
            goto error;
        }

#ifdef WIN32
        // the connection name ("Ethernet"), which open_live() and create() also accept
        if(0 == strncmp(current->name, NPF_PREFIX, strlen(NPF_PREFIX))) {
            PyObject *name = device_to_canonical(current->name + strlen(NPF_PREFIX));
            if(name && 0 > set_new(info, "name", name)) {
                goto error;
            }
        }
#endif
    }

    pcap_freealldevs(devices);
    return devdict;

error:
    pcap_freealldevs(devices);
    Py_XDECREF(devdict);
    return NULL;
}

static PyObject * PyPCAP_lookupnet(PyObject *self, PyObject *args) {
    const char *device;
    bpf_u_int32 net;
    bpf_u_int32 mask;
    struct in_addr addr;
    char network[INET_ADDRSTRLEN];
    char netmask[INET_ADDRSTRLEN];
    char errbuf[PCAP_ERRBUF_SIZE];

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

    if(0 > pcap_lookupnet(device, &net, &mask, errbuf)) {
        PyErr_SetString(PyPCAP_Error, errbuf);
        return NULL;
    }

    // both are in network byte order, ready for inet_ntop
    addr.s_addr = net;
    inet_ntop(AF_INET, &addr, network, sizeof(network));
    addr.s_addr = mask;
    inet_ntop(AF_INET, &addr, netmask, sizeof(netmask));

    return Py_BuildValue("ss", network, netmask);
}

// a new handle with no device yet
static PyPCAP * new_handle(void) {
    return (PyPCAP *)PyObject_CallNoArgs((PyObject *)&PyPCAP_Type);
}

static PyObject * PyPCAP_open_live(PyObject *self, PyObject *args) {
    PyPCAP *pypcap;
    const char *device;
    int snaplen = DEFAULT_SNAPLEN;
    int promisc = 1;
    int to_ms = 0;
    char errbuf[PCAP_ERRBUF_SIZE];

#ifdef WIN32
    char npf[MAX_PATH];
#endif

    if(!PyArg_ParseTuple(args, "s|ipi", &device, &snaplen, &promisc, &to_ms)) {
        return NULL;
    }

#ifdef WIN32
    if(0 == canonical_to_device(device, npf)) {
        device = npf;
    }
#endif

    // allocate a pcap object
    pypcap = new_handle();
    if(!pypcap) {
        return NULL;
    }

    // open the device
    pypcap->pd = pcap_open_live(device, snaplen, promisc, to_ms, errbuf);
    if(!pypcap->pd) {
        PyErr_SetString(PyPCAP_Error, errbuf);
        Py_DECREF(pypcap);
        return NULL;
    }

    snprintf(pypcap->device, sizeof(pypcap->device), "%s", device);
    pypcap->live = 1;

#ifdef WIN32
    pcap_setmintocopy(pypcap->pd, 14);
#endif

    return (PyObject *)pypcap;
}

static PyObject * PyPCAP_create(PyObject *self, PyObject *args) {
    PyPCAP *pypcap;
    const char *device;
    char errbuf[PCAP_ERRBUF_SIZE];

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

    pypcap = new_handle();
    if(!pypcap) {
        return NULL;
    }

    // unlike pcap_open_live(), an unknown device isn't reported until activate()
    pypcap->pd = pcap_create(device, errbuf);
    if(!pypcap->pd) {
        PyErr_SetString(PyPCAP_Error, errbuf);
        Py_DECREF(pypcap);
        return NULL;
    }

    snprintf(pypcap->device, sizeof(pypcap->device), "%s", device);
    pypcap->live = 1;

    return (PyObject *)pypcap;
}

// open_offline() and dump_open() take a path (str, bytes or os.PathLike), a
// file object with fileno(), or a descriptor such as a pipe from subprocess.
// A path sets *path to a bytes object; otherwise *path is NULL and *fd is set.
static int parse_target(PyObject *target, PyObject **path, int *fd) {
    PyObject *number;
    long value;

    *path = NULL;
    *fd = -1;

    if(PyLong_Check(target) || PyObject_HasAttrString(target, "fileno")) {
        if(PyLong_Check(target)) {
            number = Py_NewRef(target);
        }
        else {
            number = PyObject_CallMethod(target, "fileno", NULL);
            if(!number) {
                return -1;
            }
        }

        value = PyLong_AsLong(number);
        Py_DECREF(number);
        if(-1 == value && PyErr_Occurred()) {
            return -1;
        }

        *fd = (int)value;
        return 0;
    }

    if(0 == PyUnicode_FSConverter(target, path)) {
        if(PyErr_ExceptionMatches(PyExc_TypeError)) {
            PyErr_SetString(PyExc_TypeError, "expected a path, a file object or a file descriptor");
        }
        return -1;
    }

    return 0;
}

#ifndef WIN32
// a FILE on a duplicate of fd, so closing the handle or dumper leaves the
// caller's descriptor open; it bypasses any buffering in a Python file object
static FILE * dup_file(int fd, const char *mode) {
    FILE *fp;
    int copy;

    copy = dup(fd);
    if(0 > copy) {
        PyErr_SetString(PyPCAP_Error, strerror(errno));
        return NULL;
    }

    fp = fdopen(copy, mode);
    if(!fp) {
        PyErr_SetString(PyPCAP_Error, strerror(errno));
        close(copy);
        return NULL;
    }

    return fp;
}
#endif

static PyObject * PyPCAP_open_offline(PyObject *self, PyObject *args, PyObject *kwds) {
    static char *kwlist[] = { "file", "precision", NULL };
    PyPCAP *pypcap;
    PyObject *target;
    PyObject *path;
    const char *name;
    int precision = PCAP_TSTAMP_PRECISION_MICRO;
    int fd;
    pcap_t *pd;
    char errbuf[PCAP_ERRBUF_SIZE];

#ifdef WIN32
    intptr_t osfd = -1;
#else
    FILE *fp = NULL;
#endif

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "O|i", kwlist, &target, &precision)) {
        return NULL;
    }

    if(0 > parse_target(target, &path, &fd)) {
        return NULL;
    }

    if(!path) {
#ifdef WIN32
        if(0 > dup_handle(fd, &osfd)) {
            return NULL;
        }
#else
        fp = dup_file(fd, "rb");
        if(!fp) {
            return NULL;
        }
#endif
    }

    pypcap = new_handle();
    if(!pypcap) {
        Py_XDECREF(path);
#ifdef WIN32
        if(-1 != osfd) {
            CloseHandle((HANDLE)osfd);
        }
#else
        if(fp) {
            fclose(fp);
        }
#endif
        return NULL;
    }

    // Reading the file header blocks on a pipe or FIFO until the writer sends
    // it, and the writer may be another thread here, so release the GIL.
    // libpcap scales the file's timestamps to the requested precision.
    name = path ? PyBytes_AS_STRING(path) : NULL;
    Py_BEGIN_ALLOW_THREADS
    if(name) {
        pd = pcap_open_offline_with_tstamp_precision(name, precision, errbuf);
    }
    else {
#ifdef WIN32
        pd = pcap_hopen_offline_with_tstamp_precision(osfd, precision, errbuf);
#else
        pd = pcap_fopen_offline_with_tstamp_precision(fp, precision, errbuf);
#endif
    }
    Py_END_ALLOW_THREADS
    Py_XDECREF(path);

    if(!pd) {
        // On success pcap_close() closes the FILE; on failure it is still
        // ours. On Windows, wpcap.dll may already have wrapped the handle in a
        // FILE of its own, so it isn't closed: at worst that leaks it.
#ifndef WIN32
        if(fp) {
            fclose(fp);
        }
#endif
        PyErr_SetString(PyPCAP_Error, errbuf);
        Py_DECREF(pypcap);
        return NULL;
    }

    pypcap->pd = pd;
    return (PyObject *)pypcap;
}

static PyObject * PyPCAP_open_dead(PyObject *self, PyObject *args, PyObject *kwds) {
    static char *kwlist[] = { "linktype", "snaplen", "precision", NULL };
    PyPCAP *pypcap;
    int linktype = DLT_EN10MB;
    int snaplen = DEFAULT_SNAPLEN;
    int precision = PCAP_TSTAMP_PRECISION_MICRO;

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "|iii", kwlist, &linktype, &snaplen, &precision)) {
        return NULL;
    }

    pypcap = new_handle();
    if(!pypcap) {
        return NULL;
    }

    pypcap->pd = pcap_open_dead_with_tstamp_precision(linktype, snaplen, precision);
    if(!pypcap->pd) {
        Py_DECREF(pypcap);
        return PyErr_NoMemory();
    }

    return (PyObject *)pypcap;
}

// a number that fits in an int, or -1 with an exception set
static int int_value(PyObject *value, int *number) {
    long result;

    result = PyLong_AsLong(value);
    if(-1 == result && PyErr_Occurred()) {
        return -1;
    }

    if(INT_MIN > result || INT_MAX < result) {
        PyErr_SetString(PyExc_OverflowError, "value doesn't fit in a C int");
        return -1;
    }

    *number = (int)result;
    return 0;
}

static PyObject * PyPCAP_datalink_name_to_val(PyObject *self, PyObject *args) {
    const char *name;
    int dlt;

    name = PyUnicode_AsUTF8(args);
    if(!name) {
        return NULL;
    }

    // names as datalink() gives them, without DLT_, in any case
    dlt = pcap_datalink_name_to_val(name);
    if(0 > dlt) {
        PyErr_Format(PyPCAP_Error, "unknown link type '%s'", name);
        return NULL;
    }

    return PyLong_FromLong(dlt);
}

static PyObject * PyPCAP_datalink_val_to_name(PyObject *self, PyObject *args) {
    int dlt;

    if(0 > int_value(args, &dlt)) {
        return NULL;
    }

    return str_or_none(pcap_datalink_val_to_name(dlt));
}

static PyObject * PyPCAP_datalink_val_to_description(PyObject *self, PyObject *args) {
    int dlt;

    if(0 > int_value(args, &dlt)) {
        return NULL;
    }

    return str_or_none(pcap_datalink_val_to_description(dlt));
}

static PyObject * PyPCAP_tstamp_type_name_to_val(PyObject *self, PyObject *args) {
    const char *name;
    int type;

    name = PyUnicode_AsUTF8(args);
    if(!name) {
        return NULL;
    }

    type = pcap_tstamp_type_name_to_val(name);
    if(0 > type) {
        PyErr_Format(PyPCAP_Error, "unknown timestamp type '%s'", name);
        return NULL;
    }

    return PyLong_FromLong(type);
}

static PyObject * PyPCAP_tstamp_type_val_to_name(PyObject *self, PyObject *args) {
    int type;

    if(0 > int_value(args, &type)) {
        return NULL;
    }

    return str_or_none(pcap_tstamp_type_val_to_name(type));
}

////////////////////////////////////////////////////////////////////////////////

void PyPCAP_Type_dealloc(PyPCAP *self) {
    if(self->pd) {
        pcap_close(self->pd);
    }

    Py_TYPE(self)->tp_free((PyObject *)self);
}

// Handle() is a handle with no device; open_live() and the like open one
int PyPCAP_Type_init(PyPCAP *self, PyObject *args, PyObject *kwds) {
    static char *kwlist[] = { NULL };

    return PyArg_ParseTupleAndKeywords(args, kwds, ":Handle", kwlist) ? 0 : -1;
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

// The pcap_set_*() calls before activate() return None, or the text of a
// warning such as an unsupported timestamp type. They fail with
// PCAP_ERROR_ACTIVATED once the handle is active.
static PyObject * set_result(PyPCAP *self, int status) {
    if(0 > status) {
        // PCAP_ERROR leaves its details in the error buffer
        PyErr_SetString(PyPCAP_Error, PCAP_ERROR == status ? pcap_geterr(self->pd) : pcap_statustostr(status));
        return NULL;
    }
    else if(0 < status) {
        return PyUnicode_FromString(pcap_statustostr(status));
    }

    Py_RETURN_NONE;
}

// a setter that takes a number
static PyObject * set_number(PyPCAP *self, PyObject *args, int (*setter)(pcap_t *, int)) {
    int number;

    PCAPCTX;

    if(0 > int_value(args, &number)) {
        return NULL;
    }

    return set_result(self, setter(self->pd, number));
}

// a setter that takes a bool
static PyObject * set_flag(PyPCAP *self, PyObject *args, int (*setter)(pcap_t *, int)) {
    int flag;

    PCAPCTX;

    flag = PyObject_IsTrue(args);
    if(0 > flag) {
        return NULL;
    }

    return set_result(self, setter(self->pd, flag));
}

static PyObject * PyPCAP_set_snaplen(PyPCAP *self, PyObject *args) {
    return set_number(self, args, pcap_set_snaplen);
}

static PyObject * PyPCAP_set_promisc(PyPCAP *self, PyObject *args) {
    return set_flag(self, args, pcap_set_promisc);
}

static PyObject * PyPCAP_set_timeout(PyPCAP *self, PyObject *args) {
    return set_number(self, args, pcap_set_timeout);
}

static PyObject * PyPCAP_set_immediate_mode(PyPCAP *self, PyObject *args) {
    return set_flag(self, args, pcap_set_immediate_mode);
}

static PyObject * PyPCAP_set_buffer_size(PyPCAP *self, PyObject *args) {
    return set_number(self, args, pcap_set_buffer_size);
}

static PyObject * PyPCAP_set_rfmon(PyPCAP *self, PyObject *args) {
    return set_flag(self, args, pcap_set_rfmon);
}

static PyObject * PyPCAP_set_tstamp_type(PyPCAP *self, PyObject *args) {
    return set_number(self, args, pcap_set_tstamp_type);
}

static PyObject * PyPCAP_set_tstamp_precision(PyPCAP *self, PyObject *args) {
    return set_number(self, args, pcap_set_tstamp_precision);
}

#ifdef __linux__
// the EtherType in host byte order; libpcap converts it for socket()
static PyObject * PyPCAP_set_protocol_linux(PyPCAP *self, PyObject *args) {
    return set_number(self, args, pcap_set_protocol_linux);
}
#endif

static PyObject * PyPCAP_can_set_rfmon(PyPCAP *self) {
    int status;

    PCAPCTX;

    // libpcap only implements this for devices, and crashes on files and open_dead() handles
    if(!self->live) {
        Py_RETURN_FALSE;
    }

    status = pcap_can_set_rfmon(self->pd);
    if(0 > status) {
        PyErr_SetString(PyPCAP_Error, PCAP_ERROR == status ? pcap_geterr(self->pd) : pcap_statustostr(status));
        return NULL;
    }

    return PyBool_FromLong(status);
}

static PyObject * PyPCAP_list_tstamp_types(PyPCAP *self) {
    PyObject *types;
    PyObject *value;
    int *tstamp_types;
    int len;
    int idx;

    PCAPCTX;

    len = pcap_list_tstamp_types(self->pd, &tstamp_types);
    if(0 > len) {
        PyErr_SetString(PyPCAP_Error, pcap_geterr(self->pd));
        return NULL;
    }

    types = PyList_New(len);
    if(!types) {
        pcap_free_tstamp_types(tstamp_types);
        return NULL;
    }

    for(idx = 0; idx < len; ++idx) {
        // name/description may be NULL for unknown types; "z" maps NULL to None
        value = Py_BuildValue("izz", tstamp_types[idx],
            pcap_tstamp_type_val_to_name(tstamp_types[idx]), pcap_tstamp_type_val_to_description(tstamp_types[idx]));
        if(!value) {
            pcap_free_tstamp_types(tstamp_types);
            Py_DECREF(types);
            return NULL;
        }
        PyList_SET_ITEM(types, idx, value);
    }

    pcap_free_tstamp_types(tstamp_types);

    return types;
}

static PyObject * PyPCAP_get_tstamp_precision(PyPCAP *self) {
    PCAPCTX;

    return PyLong_FromLong(pcap_get_tstamp_precision(self->pd));
}

static PyObject * PyPCAP_geterr(PyPCAP *self) {
    PCAPCTX;

    return PyUnicode_FromString(pcap_geterr(self->pd));
}

// (dlt, name, description); name and description are None for DLTs libpcap doesn't know
static PyObject * datalink_tuple(int dlt) {
    return Py_BuildValue("izz", dlt, pcap_datalink_val_to_name(dlt), pcap_datalink_val_to_description(dlt));
}

static PyObject * PyPCAP_list_datalinks(PyPCAP *self) {
    PyObject *links;
    PyObject *value;
    int *dlts;
    int len;
    int idx;

    PCAPCTX;

    len = pcap_list_datalinks(self->pd, &dlts);
    if(0 > len) {
        PyErr_SetString(PyPCAP_Error, PCAP_ERROR == len ? pcap_geterr(self->pd) : pcap_statustostr(len));
        return NULL;
    }

    links = PyList_New(len);
    if(!links) {
        pcap_free_datalinks(dlts);
        return NULL;
    }

    for(idx = 0; idx < len; ++idx) {
        value = datalink_tuple(dlts[idx]);
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

    return datalink_tuple(dlt);
}

static PyObject * PyPCAP_set_datalink(PyPCAP *self, PyObject *args) {
    int dlt;

    PCAPCTX;

    if(0 > int_value(args, &dlt)) {
        return NULL;
    }

    if(0 > pcap_set_datalink(self->pd, dlt)) {
        PyErr_SetString(PyPCAP_Error, pcap_geterr(self->pd));
        return NULL;
    }

    Py_RETURN_NONE;
}

// pcap_major_version() and friends describe a capture file; on a live handle
// they mean nothing, or fail if it isn't activated
static PyObject * file_property(PyPCAP *self, int (*getter)(pcap_t *), int as_bool) {
    int value;

    PCAPCTX;

    value = getter(self->pd);
    if(0 > value) {
        PyErr_SetString(PyPCAP_Error, pcap_statustostr(value));
        return NULL;
    }

    return as_bool ? PyBool_FromLong(value) : PyLong_FromLong(value);
}

static PyObject * PyPCAP_major_version(PyPCAP *self) {
    return file_property(self, pcap_major_version, 0);
}

static PyObject * PyPCAP_minor_version(PyPCAP *self) {
    return file_property(self, pcap_minor_version, 0);
}

static PyObject * PyPCAP_is_swapped(PyPCAP *self) {
    return file_property(self, pcap_is_swapped, 1);
}

static PyObject * PyPCAP_setdirection(PyPCAP *self, PyObject *args) {
#ifndef WIN32
    pcap_direction_t dir;
    int status;

    PCAPCTX;

    if(!PyArg_ParseTuple(args, "i", &dir)) {
        return NULL;
    }

    // an unactivated handle gives PCAP_ERROR_NOT_ACTIVATED
    status = pcap_setdirection(self->pd, dir);
    if(0 > status) {
        PyErr_SetString(PyPCAP_Error, PCAP_ERROR == status ? pcap_geterr(self->pd) : pcap_statustostr(status));
        return NULL;
    }
#endif
    Py_RETURN_NONE;
}

static PyObject * PyPCAP_setnonblock(PyPCAP *self, PyObject *args) {
    char errbuf[PCAP_ERRBUF_SIZE];
    int nonblock;

    PCAPCTX;

    nonblock = PyObject_IsTrue(args);
    if(0 > nonblock) {
        return NULL;
    }

    if(PCAP_ERROR == pcap_setnonblock(self->pd, nonblock, errbuf)) {
        PyErr_SetString(PyPCAP_Error, errbuf);
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyObject * PyPCAP_getnonblock(PyPCAP *self) {
    char errbuf[PCAP_ERRBUF_SIZE];
    int nonblock;

    PCAPCTX;

    nonblock = pcap_getnonblock(self->pd, errbuf);
    if(PCAP_ERROR == nonblock) {
        PyErr_SetString(PyPCAP_Error, errbuf);
        return NULL;
    }

    return PyBool_FromLong(nonblock);
}

//
// Filters
//

// pcap_compile()'s netmask, which it only uses for 'ip broadcast': a dotted
// IPv4 string, or for None the device's (self is NULL without a handle), or
// unknown for files and devices without an IPv4 address. pcap_compile() wants
// it in host byte order, though pcap_lookupnet() returns network byte order.
static int parse_netmask(PyPCAP *self, PyObject *netmask, bpf_u_int32 *mask) {
    struct in_addr addr;
    bpf_u_int32 network;
    const char *text;
    char errbuf[PCAP_ERRBUF_SIZE];

    if(Py_None == netmask) {
        if(self && self->live && 0 == pcap_lookupnet(self->device, &network, mask, errbuf)) {
            *mask = ntohl(*mask);
        }
        else {
            *mask = PCAP_NETMASK_UNKNOWN;
        }
        return 0;
    }

    text = PyUnicode_Check(netmask) ? PyUnicode_AsUTF8(netmask) : NULL;
    if(!text || 1 != inet_pton(AF_INET, text, &addr)) {
        PyErr_Clear();
        PyErr_SetString(PyPCAP_Error, "netmask must be a dotted IPv4 string or None");
        return -1;
    }

    *mask = ntohl(addr.s_addr);
    return 0;
}

// a BPFProgram for pd's link type and snaplen
static PyObject * compiled_program(PyPCAP *self, pcap_t *pd, const char *expression, int optimize, PyObject *netmask) {
    PyBPF *bpf;
    bpf_u_int32 mask;

    if(0 > parse_netmask(self, netmask, &mask)) {
        return NULL;
    }

    bpf = PyObject_New(PyBPF, &PyBPF_Type);
    if(!bpf) {
        return NULL;
    }

    bpf->program.bf_len = 0;
    bpf->program.bf_insns = NULL;
    bpf->compiled = 1;

    if(0 > pcap_compile(pd, &bpf->program, expression, optimize, mask)) {
        PyErr_SetString(PyPCAP_Error, pcap_geterr(pd));
        Py_DECREF(bpf);
        return NULL;
    }

    return (PyObject *)bpf;
}

static PyObject * PyPCAP_setfilter(PyPCAP *self, PyObject *args, PyObject *kwds) {
    static char *kwlist[] = { "filter", "optimize", "netmask", NULL };
    PyObject *filter;
    PyObject *netmask = Py_None;
    PyObject *program;
    int optimize = 1;
    int status;

    PCAPCTX;
    BUSYCHECK;

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "O|pO", kwlist, &filter, &optimize, &netmask)) {
        return NULL;
    }

    if(PyObject_TypeCheck(filter, &PyBPF_Type)) {
        program = Py_NewRef(filter);
    }
    else if(PyUnicode_Check(filter)) {
        const char *expression = PyUnicode_AsUTF8(filter);
        if(!expression) {
            return NULL;
        }
        program = compiled_program(self, self->pd, expression, optimize, netmask);
        if(!program) {
            return NULL;
        }
    }
    else {
        PyErr_SetString(PyExc_TypeError, "filter must be a str or a BPFProgram");
        return NULL;
    }

    // libpcap keeps its own copy of the program
    status = pcap_setfilter(self->pd, &((PyBPF *)program)->program);
    Py_DECREF(program);

    if(0 > status) {
        PyErr_SetString(PyPCAP_Error, pcap_geterr(self->pd));
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyObject * PyPCAP_compile(PyPCAP *self, PyObject *args, PyObject *kwds) {
    static char *kwlist[] = { "expression", "optimize", "netmask", NULL };
    const char *expression;
    PyObject *netmask = Py_None;
    int optimize = 1;

    PCAPCTX;

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "s|pO", kwlist, &expression, &optimize, &netmask)) {
        return NULL;
    }

    return compiled_program(self, self->pd, expression, optimize, netmask);
}

// The module's compile(), through a temporary open_dead() handle. Unlike
// pcap_compile_nopcap(), which does the same, this keeps libpcap's error text.
static PyObject * PyPCAP_compile_dead(PyObject *self, PyObject *args, PyObject *kwds) {
    static char *kwlist[] = { "expression", "linktype", "snaplen", "optimize", "netmask", NULL };
    const char *expression;
    PyObject *netmask = Py_None;
    PyObject *program;
    int linktype = DLT_EN10MB;
    int snaplen = DEFAULT_SNAPLEN;
    int optimize = 1;
    pcap_t *pd;

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "s|iipO", kwlist, &expression, &linktype, &snaplen, &optimize, &netmask)) {
        return NULL;
    }

    pd = pcap_open_dead(linktype, snaplen);
    if(!pd) {
        return PyErr_NoMemory();
    }

    program = compiled_program(NULL, pd, expression, optimize, netmask);
    pcap_close(pd);
    return program;
}

//
// Reading packets
//

static int is_nano(pcap_t *pd) {
    return PCAP_TSTAMP_PRECISION_NANO == pcap_get_tstamp_precision(pd);
}

// (data, ts, wirelen) and then extra's items, if there are any; with
// nanosecond precision libpcap keeps nanoseconds in tv_usec
static PyObject * packet_tuple(const struct pcap_pkthdr *hdr, const u_char *data, int nano, PyObject *extra) {
    PyObject *head;
    PyObject *args;
    double ts;

    ts = (double)hdr->ts.tv_sec + (double)hdr->ts.tv_usec / (nano ? 1e9 : 1e6);

    head = Py_BuildValue("(y#dk)", data, (Py_ssize_t)hdr->caplen, ts, (unsigned long)hdr->len);
    if(!head || !extra) {
        return head;
    }

    args = PySequence_Concat(head, extra);
    Py_DECREF(head);
    return args;
}

// SIGINT hook, so Ctrl-C breaks a loop(), dispatch() or next() that is blocked
// waiting for packets. It calls pcap_breakloop() and then chains to the
// previous handler (normally Python's), so the call can raise
// KeyboardInterrupt. Only one call at a time holds the hook; calls made while
// it is taken can be stopped with breakloop(). Nothing is hooked while SIGINT
// is ignored or has its default action, which already ends the process.
static pcap_t * volatile _g_pd = NULL;

#ifdef WIN32
typedef void (*sigfunc)(int);
static sigfunc _g_prev_handler;

static void sigint_handler(int signo) {
    if(_g_pd) {
        pcap_breakloop(_g_pd);
    }
    _g_prev_handler(signo);
}

static int hook_sigint(void) {
    _g_prev_handler = signal(SIGINT, sigint_handler);
    if(SIG_DFL == _g_prev_handler || SIG_IGN == _g_prev_handler || SIG_ERR == _g_prev_handler) {
        if(SIG_ERR != _g_prev_handler) {
            signal(SIGINT, _g_prev_handler);
        }
        return 0;
    }
    return 1;
}

static void unhook_sigint(void) {
    signal(SIGINT, _g_prev_handler);
}
#else
static struct sigaction _g_prev_action;

static void sigint_handler(int signo, siginfo_t *info, void *context) {
    if(_g_pd) {
        pcap_breakloop(_g_pd);
    }
    if(_g_prev_action.sa_flags & SA_SIGINFO) {
        _g_prev_action.sa_sigaction(signo, info, context);
    }
    else {
        _g_prev_action.sa_handler(signo);
    }
}

static int hook_sigint(void) {
    struct sigaction action;

    if(0 > sigaction(SIGINT, NULL, &_g_prev_action)) {
        return 0;
    }
    if(!(_g_prev_action.sa_flags & SA_SIGINFO)
        && (SIG_DFL == _g_prev_action.sa_handler || SIG_IGN == _g_prev_action.sa_handler)) {
        return 0;
    }

    memset(&action, 0, sizeof(action));
    action.sa_sigaction = sigint_handler;
    action.sa_flags = SA_SIGINFO;
    sigemptyset(&action.sa_mask);
    return 0 == sigaction(SIGINT, &action, NULL);
}

static void unhook_sigint(void) {
    sigaction(SIGINT, &_g_prev_action, NULL);
}
#endif

// takes the hook for pd unless another call holds it; returns whether it was taken
static int acquire_sigint(pcap_t *pd) {
    if(_g_pd) {
        return 0;
    }

    _g_pd = pd;
    if(!hook_sigint()) {
        _g_pd = NULL;
        return 0;
    }

    return 1;
}

static void release_sigint(int hooked) {
    if(hooked) {
        unhook_sigint();
        _g_pd = NULL;
    }
}

// loop() and dispatch() run libpcap with the GIL released; the callback takes
// it back for each packet
typedef struct {
    PyObject      *callback;
    PyObject      *extra;    // arguments after (data, ts, wirelen), or NULL
    pcap_t        *pd;
    PyThreadState *tstate;
    pcap_dumper_t *dumper;   // written to directly instead of a callback
    int            nano;     // timestamps are in nanoseconds
    int            failed;   // the callback raised, or a signal handler did
    int            count;    // packets handled, which dispatch() returns
} loop_ctx;

static void pcap_callback(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data) {
    loop_ctx *ctx = (loop_ctx *)user;
    PyObject *args;
    PyObject *retval = NULL;

    // libpcap may still deliver the rest of its buffer after pcap_breakloop()
    if(ctx->failed) {
        return;
    }

    PyEval_RestoreThread(ctx->tstate);

    ctx->count++;

    args = packet_tuple(hdr, data, ctx->nano, ctx->extra);
    if(args) {
        retval = PyObject_CallObject(ctx->callback, args);
        Py_DECREF(args);
    }

    // an exception from the callback, or a pending signal (e.g. Ctrl-C), stops the loop
    if(!retval || 0 > PyErr_CheckSignals()) {
        ctx->failed = 1;
        pcap_breakloop(ctx->pd);
    }

    Py_XDECREF(retval);

    ctx->tstate = PyEval_SaveThread();
}

// loop(dumper) makes no Python call per packet, so the GIL stays released
static void dump_callback(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data) {
    loop_ctx *ctx = (loop_ctx *)user;

    ctx->count++;
    pcap_dump((u_char *)ctx->dumper, hdr, data);
}

static PyObject * run_loop(PyPCAP *self, PyObject *args, int dispatch) {
    pcap_handler handler = pcap_callback;
    PyDumper *dumper = NULL;
    Py_ssize_t len;
    loop_ctx ctx;
    int cnt = -1;
    int hooked;
    int retval;

    PCAPCTX;
    BUSYCHECK;

    len = PyTuple_GET_SIZE(args);
    if(len == 0) {
        PyErr_Format(PyExc_TypeError, "%s() needs a callback", dispatch ? "dispatch" : "loop");
        return NULL;
    }

    if(1 < len && 0 > int_value(PyTuple_GET_ITEM(args, 1), &cnt)) {
        return NULL;
    }

    memset(&ctx, 0, sizeof(ctx));
    ctx.callback = PyTuple_GET_ITEM(args, 0);
    ctx.pd = self->pd;
    ctx.nano = is_nano(self->pd);

    // packets for a dumper go straight to pcap_dump(), keeping their capture timestamps
    if(PyObject_TypeCheck(ctx.callback, &PyDumper_Type)) {
        dumper = (PyDumper *)ctx.callback;
        if(!dumper->dumper) {
            PyErr_SetString(PyPCAP_Error, "dumper is closed");
            return NULL;
        }
        if(dumper->busy) {
            PyErr_SetString(PyPCAP_Error, "dumper is busy in loop()");
            return NULL;
        }
        if(2 < len) {
            PyErr_SetString(PyExc_TypeError, "a Dumper takes no extra arguments");
            return NULL;
        }
        ctx.dumper = dumper->dumper;
        handler = dump_callback;
    }
    else if(!PyCallable_Check(ctx.callback)) {
        PyErr_SetString(PyPCAP_Error, "Invalid callback");
        return NULL;
    }
    else if(2 < len) {
        ctx.extra = PyTuple_GetSlice(args, 2, len);
        if(!ctx.extra) {
            return NULL;
        }
    }

    hooked = acquire_sigint(self->pd);
    self->busy = 1;
    if(dumper) {
        dumper->busy = 1;
    }

    ctx.tstate = PyEval_SaveThread();
    if(dispatch) {
        retval = pcap_dispatch(self->pd, cnt, handler, (u_char *)&ctx);
    }
    else {
        retval = pcap_loop(self->pd, cnt, handler, (u_char *)&ctx);
    }
    PyEval_RestoreThread(ctx.tstate);

    self->busy = 0;
    if(dumper) {
        dumper->busy = 0;
    }
    release_sigint(hooked);
    Py_XDECREF(ctx.extra);

    // the callback raised, or a signal handler did
    if(ctx.failed) {
        return NULL;
    }

    // Ctrl-C ends the loop with PCAP_ERROR_BREAK, or with PCAP_ERROR when it
    // interrupts a blocking read; either way, raise KeyboardInterrupt instead
    if(0 > retval && 0 > PyErr_CheckSignals()) {
        return NULL;
    }

    // PCAP_ERROR_BREAK is breakloop()
    if(PCAP_ERROR == retval) {
        PyErr_SetString(PyPCAP_Error, pcap_geterr(self->pd));
        return NULL;
    }
    else if(0 > retval && PCAP_ERROR_BREAK != retval) {
        PyErr_SetString(PyPCAP_Error, pcap_statustostr(retval));
        return NULL;
    }

    // count the packets rather than trust pcap_dispatch(): on a file, macOS's
    // libpcap 1.10.1 returns 0 at the end even after handling some
    if(dispatch) {
        return PyLong_FromLong(ctx.count);
    }

    Py_RETURN_NONE;
}

static PyObject * PyPCAP_loop(PyPCAP *self, PyObject *args) {
    return run_loop(self, args, 0);
}

static PyObject * PyPCAP_dispatch(PyPCAP *self, PyObject *args) {
    return run_loop(self, args, 1);
}

static PyObject * PyPCAP_breakloop(PyPCAP *self) {
    PCAPCTX;

    pcap_breakloop(self->pd);

    Py_RETURN_NONE;
}

// returned by read_packet() once it has set an exception
#define READ_RAISED (-100)

// one pcap_next_ex() for next() and iteration, with the GIL released and the
// Ctrl-C hook taken: 1 for a packet, 0 when a live read timed out or found
// nothing in non-blocking mode, PCAP_ERROR_BREAK at the end of a file or after
// breakloop(), or READ_RAISED
static int read_packet(PyPCAP *self, struct pcap_pkthdr **hdr, const u_char **data) {
    int hooked;
    int retval;

    hooked = acquire_sigint(self->pd);
    self->busy = 1;

    Py_BEGIN_ALLOW_THREADS
    retval = pcap_next_ex(self->pd, hdr, data);
    Py_END_ALLOW_THREADS

    self->busy = 0;
    release_sigint(hooked);

    // as in loop(): Ctrl-C during a blocked read raises KeyboardInterrupt
    if(0 > retval && 0 > PyErr_CheckSignals()) {
        return READ_RAISED;
    }

    if(PCAP_ERROR == retval) {
        PyErr_SetString(PyPCAP_Error, pcap_geterr(self->pd));
        return READ_RAISED;
    }
    else if(0 > retval && PCAP_ERROR_BREAK != retval) {
        PyErr_SetString(PyPCAP_Error, pcap_statustostr(retval));
        return READ_RAISED;
    }

    return retval;
}

static PyObject * PyPCAP_next_ex(PyPCAP *self) {
    struct pcap_pkthdr *hdr;
    const u_char *data;
    int retval;

    PCAPCTX;
    BUSYCHECK;

    retval = read_packet(self, &hdr, &data);
    if(1 == retval) {
        return packet_tuple(hdr, data, is_nano(self->pd), NULL);
    }
    else if(0 == retval) {
        // timeout, or nothing available in non-blocking mode
        Py_RETURN_NONE;
    }
    else if(PCAP_ERROR_BREAK == retval) {
        PyErr_SetNone(PyExc_EOFError);
        return NULL;
    }

    return NULL;
}

PyObject * PyPCAP_Type_iter(PyPCAP *self) {
    PyPacketIter *iter;

    PCAPCTX;

    iter = PyObject_New(PyPacketIter, &PyPacketIter_Type);
    if(!iter) {
        return NULL;
    }

    iter->handle = (PyPCAP *)Py_NewRef(self);

    return (PyObject *)iter;
}

void PyPacketIter_Type_dealloc(PyPacketIter *self) {
    Py_DECREF(self->handle);
    PyObject_Free(self);
}

// Ends at the end of a file or after breakloop(). A live read that times out
// keeps waiting, except in non-blocking mode, where iteration ends once no
// packet is ready, so a select() loop can drain the handle with a for loop.
PyObject * PyPacketIter_Type_iternext(PyPacketIter *iter) {
    PyPCAP *self = iter->handle;
    struct pcap_pkthdr *hdr;
    const u_char *data;
    char errbuf[PCAP_ERRBUF_SIZE];
    int retval;

    for(;;) {
        PCAPCTX;
        BUSYCHECK;

        retval = read_packet(self, &hdr, &data);
        if(1 == retval) {
            return packet_tuple(hdr, data, is_nano(self->pd), NULL);
        }
        else if(0 != retval) {
            // the end, or READ_RAISED
            return NULL;
        }

        if(0 < pcap_getnonblock(self->pd, errbuf)) {
            return NULL;
        }
        if(0 > PyErr_CheckSignals()) {
            return NULL;
        }
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

// Some platforms can't wake select() when packets arrive, so it must time out
// this often and then read; None when there is no such limit.
static PyObject * PyPCAP_get_required_select_timeout(PyPCAP *self) {
    const struct timeval *timeout;

    PCAPCTX;

    timeout = pcap_get_required_select_timeout(self->pd);
    if(!timeout) {
        Py_RETURN_NONE;
    }

    return PyFloat_FromDouble((double)timeout->tv_sec + (double)timeout->tv_usec / 1e6);
}
#endif

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

static PyObject * PyPCAP_bufsize(PyPCAP *self) {
    int size;

    PCAPCTX;

    size = pcap_bufsize(self->pd);
    if(0 > size) {
        PyErr_SetString(PyPCAP_Error, pcap_statustostr(size));
        return NULL;
    }

    return PyLong_FromLong(size);
}

static PyObject * PyPCAP_close(PyPCAP *self) {
    BUSYCHECK;

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

static PyObject * PyPCAP_enter(PyPCAP *self) {
    PCAPCTX;

    return Py_NewRef(self);
}

static PyObject * PyPCAP_exit(PyPCAP *self, PyObject *args) {
    return PyPCAP_close(self);
}

//
// Compiled programs
//

// one (code, jt, jf, k) instruction, as a tuple or list; -1 if it isn't one
static int parse_insn(PyObject *item, struct bpf_insn *insn) {
    static const unsigned long long limits[4] = { 0xffff, 0xff, 0xff, 0xffffffff };
    unsigned long long fields[4];
    PyObject *field;
    int idx;

    if(!(PyTuple_Check(item) || PyList_Check(item)) || 4 != PySequence_Fast_GET_SIZE(item)) {
        return -1;
    }

    for(idx = 0; idx < 4; ++idx) {
        field = PySequence_Fast_GET_ITEM(item, idx);
        if(!PyLong_Check(field)) {
            return -1;
        }

        fields[idx] = PyLong_AsUnsignedLongLong(field);
        if((unsigned long long)-1 == fields[idx] && PyErr_Occurred()) {
            // OverflowError, for a negative or huge number
            PyErr_Clear();
            return -1;
        }

        if(fields[idx] > limits[idx]) {
            return -1;
        }
    }

    insn->code = (u_short)fields[0];
    insn->jt   = (u_char)fields[1];
    insn->jf   = (u_char)fields[2];
    insn->k    = (bpf_u_int32)fields[3];
    return 0;
}

// BPFProgram(instructions): a program from (code, jt, jf, k) tuples, such as
// list(program) or the lines of tcpdump -ddd, checked with bpf_validate()
PyObject * PyBPF_Type_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
    static char *kwlist[] = { "instructions", NULL };
    PyObject *instructions;
    PyObject *items;
    PyBPF *bpf;
    Py_ssize_t count;
    Py_ssize_t idx;

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "O:BPFProgram", kwlist, &instructions)) {
        return NULL;
    }

    items = PySequence_Fast(instructions, "instructions must be an iterable of (code, jt, jf, k) tuples");
    if(!items) {
        return NULL;
    }

    count = PySequence_Fast_GET_SIZE(items);
    if(count > INT_MAX) {
        Py_DECREF(items);
        PyErr_SetString(PyPCAP_Error, "too many instructions");
        return NULL;
    }

    bpf = (PyBPF *)type->tp_alloc(type, 0);
    if(!bpf) {
        Py_DECREF(items);
        return NULL;
    }

    // PyMem_New(0) still returns a pointer, so an empty program fails below
    bpf->program.bf_insns = PyMem_New(struct bpf_insn, count);
    if(!bpf->program.bf_insns) {
        Py_DECREF(items);
        Py_DECREF(bpf);
        return PyErr_NoMemory();
    }
    bpf->program.bf_len = (u_int)count;

    for(idx = 0; idx < count; ++idx) {
        if(0 > parse_insn(PySequence_Fast_GET_ITEM(items, idx), &bpf->program.bf_insns[idx])) {
            PyErr_Format(PyPCAP_Error, "instruction %zd must be (code, jt, jf, k), with code below 65536, "
                         "jt and jf below 256, and k below 2**32", idx);
            Py_DECREF(items);
            Py_DECREF(bpf);
            return NULL;
        }
    }
    Py_DECREF(items);

    if(!bpf_validate(bpf->program.bf_insns, (int)count)) {
        PyErr_SetString(PyPCAP_Error, "invalid BPF program: it needs known opcodes, "
                        "jumps that stay inside it, and a return at the end");
        Py_DECREF(bpf);
        return NULL;
    }

    return (PyObject *)bpf;
}

void PyBPF_Type_dealloc(PyBPF *self) {
    // libpcap frees what pcap_compile() allocated. A program built from tuples
    // is ours, and on Windows wpcap.dll may free with another C runtime.
    if(self->compiled) {
        pcap_freecode(&self->program);
    }
    else {
        PyMem_Free(self->program.bf_insns);
    }

    Py_TYPE(self)->tp_free((PyObject *)self);
}

Py_ssize_t PyBPF_Type_len(PyBPF *self) {
    return self->program.bf_len;
}

// program[index] is (code, jt, jf, k), as tcpdump -ddd prints it
PyObject * PyBPF_Type_item(PyBPF *self, Py_ssize_t index) {
    const struct bpf_insn *insn;

    if(0 > index || index >= (Py_ssize_t)self->program.bf_len) {
        PyErr_SetString(PyExc_IndexError, "instruction index out of range");
        return NULL;
    }

    insn = &self->program.bf_insns[index];
    return Py_BuildValue("(HBBI)", insn->code, insn->jt, insn->jf, insn->k);
}

static PyObject * PyBPF_match(PyBPF *self, PyObject *args) {
    struct pcap_pkthdr hdr;
    Py_buffer packet;
    int matched;

    if(0 > PyObject_GetBuffer(args, &packet, PyBUF_SIMPLE)) {
        return NULL;
    }

    memset(&hdr, 0, sizeof(hdr));
    hdr.caplen = (bpf_u_int32)packet.len;
    hdr.len = (bpf_u_int32)packet.len;

    matched = pcap_offline_filter(&self->program, &hdr, packet.buf);
    PyBuffer_Release(&packet);

    return PyBool_FromLong(matched);
}

static PyObject * PyBPF_instructions(PyBPF *self) {
    PyObject *lines;
    PyObject *line;
    u_int idx;

    lines = PyList_New(self->program.bf_len);
    if(!lines) {
        return NULL;
    }

    for(idx = 0; idx < self->program.bf_len; ++idx) {
        // bpf_image() formats one instruction as "(000) ldh      [12]"
        line = PyUnicode_FromString(bpf_image(&self->program.bf_insns[idx], (int)idx));
        if(!line) {
            Py_DECREF(lines);
            return NULL;
        }
        PyList_SET_ITEM(lines, idx, line);
    }

    return lines;
}

//
// Capture files
//

#define DUMPCHECK if(NULL == self->dumper) { PyErr_SetString(PyPCAP_Error, "dumper is closed"); return NULL; }
#define DUMPBUSYCHECK if(self->busy) { PyErr_SetString(PyPCAP_Error, "dumper is busy in loop()"); return NULL; }

static PyObject * PyPCAP_dump_open(PyPCAP *self, PyObject *args, PyObject *kwds) {
    static char *kwlist[] = { "file", "append", NULL };
    PyDumper *dumper;
    PyObject *target;
    PyObject *path;
    int append = 0;
    int snaplen;
    int fd;

    PCAPCTX;

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "O|p", kwlist, &target, &append)) {
        return NULL;
    }

    // an unactivated handle has no link type or snaplen for the file header yet
    snaplen = pcap_snapshot(self->pd);
    if(0 > snaplen) {
        PyErr_SetString(PyPCAP_Error, pcap_statustostr(snaplen));
        return NULL;
    }

    if(0 > parse_target(target, &path, &fd)) {
        return NULL;
    }

    if(append && !path) {
        PyErr_SetString(PyPCAP_Error, "append needs a path");
        return NULL;
    }

    dumper = PyObject_New(PyDumper, &PyDumper_Type);
    if(!dumper) {
        Py_XDECREF(path);
        return NULL;
    }

    dumper->dumper = NULL;
    dumper->snaplen = snaplen;
    dumper->nano = is_nano(self->pd);
    dumper->busy = 0;

    // the file header takes its link type and snaplen from this handle
    if(!path) {
        // on failure libpcap may already have closed the duplicate, so it
        // isn't closed here; at worst that leaks it
#ifdef WIN32
        intptr_t osfd;
        if(0 > dup_handle(fd, &osfd)) {
            Py_DECREF(dumper);
            return NULL;
        }
        dumper->dumper = pcap_dump_hopen(self->pd, osfd);
#else
        FILE *fp = dup_file(fd, "wb");
        if(!fp) {
            Py_DECREF(dumper);
            return NULL;
        }
        dumper->dumper = pcap_dump_fopen(self->pd, fp);
#endif
    }
    else if(append) {
        dumper->dumper = pcap_dump_open_append(self->pd, PyBytes_AS_STRING(path));
    }
    else {
        dumper->dumper = pcap_dump_open(self->pd, PyBytes_AS_STRING(path));
    }
    Py_XDECREF(path);

    if(!dumper->dumper) {
        PyErr_SetString(PyPCAP_Error, pcap_geterr(self->pd));
        Py_DECREF(dumper);
        return NULL;
    }

    return (PyObject *)dumper;
}

void PyDumper_Type_dealloc(PyDumper *self) {
    if(self->dumper) {
        pcap_dump_close(self->dumper);
    }

    PyObject_Free(self);
}

static void timestamp_now(struct timeval *tv) {
#ifdef WIN32
    struct timespec now;

    timespec_get(&now, TIME_UTC);
    tv->tv_sec = (long)now.tv_sec;
    tv->tv_usec = now.tv_nsec / 1000;
#else
    gettimeofday(tv, NULL);
#endif
}

// A pcap_pkthdr for length bytes written from Python: ts in seconds (None for
// now) at the given precision, and wirelen (None for the length). Like a
// capture, at most snaplen bytes are kept.
static int fill_header(struct pcap_pkthdr *hdr, Py_ssize_t length, PyObject *ts, PyObject *wirelen, int nano, int snaplen) {
    Py_ssize_t original = -1;
    double seconds;
    double whole;
    long fraction;
    long scale;

    if(Py_None != wirelen) {
        original = PyLong_AsSsize_t(wirelen);
        if(-1 == original && PyErr_Occurred()) {
            return -1;
        }
        if(original < length) {
            PyErr_SetString(PyPCAP_Error, "wirelen is shorter than the packet");
            return -1;
        }
    }

    // at nanosecond precision, tv_usec holds nanoseconds
    scale = nano ? 1000000000 : 1000000;

    if(Py_None == ts) {
        timestamp_now(&hdr->ts);
        if(nano) {
            hdr->ts.tv_usec *= 1000;
        }
    }
    else {
        seconds = PyFloat_AsDouble(ts);
        if(-1.0 == seconds && PyErr_Occurred()) {
            return -1;
        }

        whole = floor(seconds);
        fraction = (long)((seconds - whole) * scale + 0.5);
        if(scale <= fraction) {
            whole += 1;
            fraction -= scale;
        }

        hdr->ts.tv_sec = (long)whole;
        hdr->ts.tv_usec = fraction;
    }

    hdr->len = (bpf_u_int32)(0 <= original ? original : length);
    hdr->caplen = (bpf_u_int32)(length < snaplen ? length : snaplen);

    return 0;
}

static PyObject * PyDumper_write(PyDumper *self, PyObject *args, PyObject *kwds) {
    static char *kwlist[] = { "data", "ts", "wirelen", NULL };
    struct pcap_pkthdr hdr;
    Py_buffer packet;
    PyObject *ts = Py_None;
    PyObject *wirelen = Py_None;

    DUMPCHECK;
    DUMPBUSYCHECK;

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "y*|OO", kwlist, &packet, &ts, &wirelen)) {
        return NULL;
    }

    if(0 > fill_header(&hdr, packet.len, ts, wirelen, self->nano, self->snaplen)) {
        PyBuffer_Release(&packet);
        return NULL;
    }

    pcap_dump((u_char *)self->dumper, &hdr, packet.buf);
    PyBuffer_Release(&packet);

    Py_RETURN_NONE;
}

static PyObject * PyDumper_flush(PyDumper *self) {
    DUMPCHECK;

    if(0 > pcap_dump_flush(self->dumper)) {
        PyErr_SetString(PyPCAP_Error, strerror(errno));
        return NULL;
    }

    Py_RETURN_NONE;
}

// where the next packet goes, so a caller can start a new file at some size;
// fails on a pipe
static PyObject * PyDumper_tell(PyDumper *self) {
    int64_t position;

    DUMPCHECK;

    position = pcap_dump_ftell64(self->dumper);
    if(0 > position) {
        PyErr_SetString(PyPCAP_Error, strerror(errno));
        return NULL;
    }

    return PyLong_FromLongLong(position);
}

static PyObject * PyDumper_close(PyDumper *self) {
    int flushed;
    int err;

    DUMPBUSYCHECK;

    if(!self->dumper) {
        Py_RETURN_NONE;
    }

    // pcap_dump_close() doesn't report errors, so flush first to catch a failed write
    flushed = pcap_dump_flush(self->dumper);
    err = errno;
    pcap_dump_close(self->dumper);
    self->dumper = NULL;

    if(0 > flushed) {
        PyErr_SetString(PyPCAP_Error, strerror(err));
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyObject * PyDumper_enter(PyDumper *self) {
    DUMPCHECK;

    return Py_NewRef(self);
}

static PyObject * PyDumper_exit(PyDumper *self, PyObject *args) {
    return PyDumper_close(self);
}

#include "win32.c"
