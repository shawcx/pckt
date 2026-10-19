
#ifdef WIN32

static PyObject * PyPCAP_getevent(PyPCAP *self) {
    PCAPCTX;

    // a HANDLE is a pointer, too wide for a long on 64-bit Windows
    return PyLong_FromVoidPtr(pcap_getevent(self->pd));
}

/*
 * Npcap: driver settings, statistics and adapter OIDs
 */

static PyObject * PyPCAP_setbuff(PyPCAP *self, PyObject *args) {
    return set_number(self, args, pcap_setbuff);
}

static PyObject * PyPCAP_setmintocopy(PyPCAP *self, PyObject *args) {
    return set_number(self, args, pcap_setmintocopy);
}

static PyObject * PyPCAP_setuserbuffer(PyPCAP *self, PyObject *args) {
    // it frees the buffer that a running loop() reads packets from
    BUSYCHECK;

    return set_number(self, args, pcap_setuserbuffer);
}

static PyObject * PyPCAP_setmode(PyPCAP *self, PyObject *args) {
    return set_number(self, args, pcap_setmode);
}

static PyObject * PyPCAP_stats_ex(PyPCAP *self) {
    struct pcap_stat *ps;
    int size;

    PCAPCTX;

    ps = pcap_stats_ex(self->pd, &size);
    if(!ps) {
        PyErr_SetString(PyPCAP_Error, pcap_geterr(self->pd));
        return NULL;
    }

    return Py_BuildValue("{s:I,s:I,s:I,s:I,s:I,s:I}",
        "recv",    ps->ps_recv,
        "drop",    ps->ps_drop,
        "ifdrop",  ps->ps_ifdrop,
        "capt",    ps->ps_capt,
        "sent",    ps->ps_sent,
        "netdrop", ps->ps_netdrop);
}

static PyObject * PyPCAP_oid_get_request(PyPCAP *self, PyObject *args) {
    PyObject *result;
    unsigned int oid;
    Py_ssize_t size;
    size_t len;
    void *buf;

    PCAPCTX;

    if(!PyArg_ParseTuple(args, "In", &oid, &size)) {
        return NULL;
    }

    if(0 > size) {
        PyErr_SetString(PyPCAP_Error, "size must not be negative");
        return NULL;
    }

    buf = PyMem_Malloc(size ? size : 1);
    if(!buf) {
        return PyErr_NoMemory();
    }

    // the driver shortens len to what it returned
    len = (size_t)size;
    if(0 > pcap_oid_get_request(self->pd, oid, buf, &len)) {
        PyMem_Free(buf);
        PyErr_SetString(PyPCAP_Error, pcap_geterr(self->pd));
        return NULL;
    }

    result = PyBytes_FromStringAndSize(buf, (Py_ssize_t)len);
    PyMem_Free(buf);
    return result;
}

static PyObject * PyPCAP_oid_set_request(PyPCAP *self, PyObject *args) {
    unsigned int oid;
    Py_buffer data;
    size_t len;
    int status;

    PCAPCTX;

    if(!PyArg_ParseTuple(args, "Iy*", &oid, &data)) {
        return NULL;
    }

    len = (size_t)data.len;
    status = pcap_oid_set_request(self->pd, oid, data.buf, &len);
    PyBuffer_Release(&data);

    if(0 > status) {
        PyErr_SetString(PyPCAP_Error, pcap_geterr(self->pd));
        return NULL;
    }

    Py_RETURN_NONE;
}

/*
 * Npcap: send queues
 */

PyObject * PySendQueue_Type_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
    static char *kwlist[] = { "memsize", NULL };
    PySendQueue *self;
    unsigned int memsize;

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "I:SendQueue", kwlist, &memsize)) {
        return NULL;
    }

    self = (PySendQueue *)type->tp_alloc(type, 0);
    if(!self) {
        return NULL;
    }

    self->queue = pcap_sendqueue_alloc(memsize);
    if(!self->queue) {
        Py_DECREF(self);
        return PyErr_NoMemory();
    }

    return (PyObject *)self;
}

void PySendQueue_Type_dealloc(PySendQueue *self) {
    if(self->queue) {
        pcap_sendqueue_destroy(self->queue);
    }

    Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject * PySendQueue_queue(PySendQueue *self, PyObject *args, PyObject *kwds) {
    static char *kwlist[] = { "data", "ts", "wirelen", NULL };
    struct pcap_pkthdr hdr;
    Py_buffer packet;
    PyObject *ts = Py_None;
    PyObject *wirelen = Py_None;
    int status;

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "y*|OO", kwlist, &packet, &ts, &wirelen)) {
        return NULL;
    }

    // timestamps only matter relative to each other, for sync transmits
    if(0 > fill_header(&hdr, packet.len, ts, wirelen, 0, INT_MAX)) {
        PyBuffer_Release(&packet);
        return NULL;
    }

    status = pcap_sendqueue_queue(self->queue, &hdr, packet.buf);
    PyBuffer_Release(&packet);

    if(0 > status) {
        PyErr_SetString(PyPCAP_Error, "send queue is full");
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyObject * PySendQueue_size(PySendQueue *self, void *closure) {
    return PyLong_FromUnsignedLong(self->queue->maxlen);
}

static PyObject * PySendQueue_used(PySendQueue *self, void *closure) {
    return PyLong_FromUnsignedLong(self->queue->len);
}

static PyObject * PyPCAP_sendqueue_transmit(PyPCAP *self, PyObject *args, PyObject *kwds) {
    static char *kwlist[] = { "queue", "sync", NULL };
    PySendQueue *queue;
    int sync = 0;
    u_int sent;

    PCAPCTX;
    BUSYCHECK;

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "O!|p", kwlist, &PySendQueue_Type, &queue, &sync)) {
        return NULL;
    }

    // with sync, the driver waits between packets to match their timestamps
    self->busy = 1;
    Py_BEGIN_ALLOW_THREADS
    sent = pcap_sendqueue_transmit(self->pd, queue->queue, sync);
    Py_END_ALLOW_THREADS
    self->busy = 0;

    if(sent < queue->queue->len) {
        PyErr_SetString(PyPCAP_Error, pcap_geterr(self->pd));
        return NULL;
    }

    return PyLong_FromUnsignedLong(sent);
}

/*
 * Npcap: remote capture over rpcap (passive mode)
 */

// username and password for pcap_open() and pcap_findalldevs_ex(), or NULL for no authentication
static struct pcap_rmtauth * remote_auth(struct pcap_rmtauth *auth, const char *username, const char *password) {
    if(!username && !password) {
        return NULL;
    }

    memset(auth, 0, sizeof(*auth));
    auth->type = RPCAP_RMTAUTH_PWD;
    auth->username = (char *)username;
    auth->password = (char *)password;
    return auth;
}

static PyObject * PyPCAP_open_remote(PyObject *self, PyObject *args, PyObject *kwds) {
    static char *kwlist[] = { "source", "snaplen", "flags", "timeout_ms", "username", "password", NULL };
    PyPCAP *pypcap;
    const char *source;
    const char *username = NULL;
    const char *password = NULL;
    int snaplen = DEFAULT_SNAPLEN;
    int flags = 0;
    int to_ms = 100;
    struct pcap_rmtauth auth;
    struct pcap_rmtauth *authp;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pd;

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "s|iiizz", kwlist,
            &source, &snaplen, &flags, &to_ms, &username, &password)) {
        return NULL;
    }

    pypcap = new_handle();
    if(!pypcap) {
        return NULL;
    }

    // connecting to a remote host can take a while
    authp = remote_auth(&auth, username, password);
    Py_BEGIN_ALLOW_THREADS
    pd = pcap_open(source, snaplen, flags, to_ms, authp, errbuf);
    Py_END_ALLOW_THREADS

    if(!pd) {
        PyErr_SetString(PyPCAP_Error, errbuf);
        Py_DECREF(pypcap);
        return NULL;
    }

    // live stays 0: a file:// source is a savefile, where pcap_can_set_rfmon() crashes
    pypcap->pd = pd;
    snprintf(pypcap->device, sizeof(pypcap->device), "%s", source);
    return (PyObject *)pypcap;
}

static PyObject * PyPCAP_find_remote(PyObject *self, PyObject *args, PyObject *kwds) {
    static char *kwlist[] = { "source", "username", "password", NULL };
    PyObject *devdict;
    const char *source;
    const char *username = NULL;
    const char *password = NULL;
    struct pcap_rmtauth auth;
    struct pcap_rmtauth *authp;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *devices;
    pcap_if_t *current;
    int status;

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "s|zz", kwlist, &source, &username, &password)) {
        return NULL;
    }

    authp = remote_auth(&auth, username, password);
    Py_BEGIN_ALLOW_THREADS
    status = pcap_findalldevs_ex(source, authp, &devices, errbuf);
    Py_END_ALLOW_THREADS

    if(0 > status) {
        PyErr_SetString(PyPCAP_Error, errbuf);
        return NULL;
    }

    // keyed by their rpcap:// names
    devdict = PyDict_New();
    for(current = devices; devdict && current; current = current->next) {
        if(0 > set_new(devdict, current->name, describe_device(current))) {
            Py_CLEAR(devdict);
        }
    }

    pcap_freealldevs(devices);
    return devdict;
}

static PyObject * PyPCAP_createsrcstr(PyObject *self, PyObject *args, PyObject *kwds) {
    static char *kwlist[] = { "type", "host", "port", "name", NULL };
    const char *host = NULL;
    const char *port = NULL;
    const char *name = NULL;
    int type;
    char source[PCAP_BUF_SIZE];
    char errbuf[PCAP_ERRBUF_SIZE];

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "i|zzz", kwlist, &type, &host, &port, &name)) {
        return NULL;
    }

    if(0 > pcap_createsrcstr(source, type, host, port, name, errbuf)) {
        PyErr_SetString(PyPCAP_Error, errbuf);
        return NULL;
    }

    return PyUnicode_FromString(source);
}

static PyObject * PyPCAP_parsesrcstr(PyObject *self, PyObject *args) {
    const char *source;
    int type;
    char host[PCAP_BUF_SIZE];
    char port[PCAP_BUF_SIZE];
    char name[PCAP_BUF_SIZE];
    char errbuf[PCAP_ERRBUF_SIZE];

    source = PyUnicode_AsUTF8(args);
    if(!source) {
        return NULL;
    }

    if(0 > pcap_parsesrcstr(source, &type, host, port, name, errbuf)) {
        PyErr_SetString(PyPCAP_Error, errbuf);
        return NULL;
    }

    // parts the source doesn't have come back empty; return them as None
    return Py_BuildValue("(izzz)", type, host[0] ? host : NULL, port[0] ? port : NULL, name[0] ? name : NULL);
}

/*
 * rpcap active mode: an `rpcapd -a` connects to us rather than the other way
 * round. remoteact_accept() waits for one connection, and libpcap keeps it, so
 * open_remote() and find_remote() then reach that host through it with sources
 * such as rpcap://<host>/. libpcap keeps these hosts in a global list without
 * a lock; holding the GIL serializes everything but the accept itself.
 */

static int _g_accepting = 0;         // a remoteact_accept() waits with the GIL released
static int _g_accept_cancelled = 0;  // and remoteact_cleanup() has been called for it

static PyObject * PyPCAP_remoteact_accept(PyObject *self, PyObject *args, PyObject *kwds) {
    static char *kwlist[] = { "address", "port", "hostlist", "username", "password", "ssl", NULL };
    const char *address = NULL;
    const char *port = NULL;
    const char *hostlist = NULL;
    const char *username = NULL;
    const char *password = NULL;
    int ssl = 0;
    struct pcap_rmtauth auth;
    struct pcap_rmtauth *authp;
    char host[RPCAP_HOSTLIST_SIZE];
    char errbuf[PCAP_ERRBUF_SIZE];
    SOCKET sock;

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "|zzzzzp", kwlist,
            &address, &port, &hostlist, &username, &password, &ssl)) {
        return NULL;
    }

    // libpcap listens on a single global socket, which a second call would replace
    if(_g_accepting) {
        PyErr_SetString(PyPCAP_Error, "remoteact_accept() is already waiting in another thread");
        return NULL;
    }
    _g_accepting = 1;
    _g_accept_cancelled = 0;

    // this blocks until a connection comes; remoteact_cleanup() from another thread stops it
    authp = remote_auth(&auth, username, password);
    Py_BEGIN_ALLOW_THREADS
    sock = pcap_remoteact_accept_ex(address, port, hostlist, host, authp, ssl, errbuf);
    Py_END_ALLOW_THREADS
    _g_accepting = 0;

    // -1, -2 and -3 tell apart failures that all leave a message in errbuf
    if((SOCKET)-1 == sock || (SOCKET)-2 == sock || (SOCKET)-3 == sock) {
        PyErr_SetString(PyPCAP_Error, _g_accept_cancelled ? "remoteact_accept() was stopped by remoteact_cleanup()" : errbuf);
        return NULL;
    }

    // libpcap owns the connection; remoteact_close(host) ends it
    return PyUnicode_FromString(host);
}

static PyObject * PyPCAP_remoteact_list(PyObject *self) {
    // Whatever size it's given, libpcap appends each host with a limit of
    // PCAP_ERRBUF_SIZE, so a longer list in a bigger buffer would come back
    // garbled. At this size it reports the overflow instead.
    char hostlist[PCAP_ERRBUF_SIZE];
    char errbuf[PCAP_ERRBUF_SIZE];
    PyObject *hosts;
    PyObject *host;
    char *start;
    char *end;

    if(0 > pcap_remoteact_list(hostlist, ',', (int)sizeof(hostlist), errbuf)) {
        PyErr_SetString(PyPCAP_Error, errbuf);
        return NULL;
    }

    hosts = PyList_New(0);
    if(!hosts) {
        return NULL;
    }

    // each host is followed by the separator
    for(start = hostlist; NULL != (end = strchr(start, ',')); start = end + 1) {
        host = PyUnicode_FromStringAndSize(start, end - start);
        if(!host || 0 > PyList_Append(hosts, host)) {
            Py_XDECREF(host);
            Py_DECREF(hosts);
            return NULL;
        }
        Py_DECREF(host);
    }

    return hosts;
}

static PyObject * PyPCAP_remoteact_close(PyObject *self, PyObject *args) {
    const char *host;
    char errbuf[PCAP_ERRBUF_SIZE];

    host = PyUnicode_AsUTF8(args);
    if(!host) {
        return NULL;
    }

    // keeps the GIL while it removes the host from libpcap's list
    if(0 > pcap_remoteact_close(host, errbuf)) {
        PyErr_SetString(PyPCAP_Error, errbuf);
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyObject * PyPCAP_remoteact_cleanup(PyObject *self) {
    // closes the socket a remoteact_accept() in another thread waits on, so
    // that call fails; with none waiting, this does nothing
    if(_g_accepting) {
        _g_accept_cancelled = 1;
    }

    pcap_remoteact_cleanup();

    Py_RETURN_NONE;
}

static PyObject * PyPCAP_setsampling(PyPCAP *self, PyObject *args) {
    struct pcap_samp *sampling;
    int method;
    int value;

    PCAPCTX;

    if(!PyArg_ParseTuple(args, "ii", &method, &value)) {
        return NULL;
    }

    // libpcap sends these to the rpcap server when the capture starts
    sampling = pcap_setsampling(self->pd);
    sampling->method = method;
    sampling->value = value;

    Py_RETURN_NONE;
}

/*
 * Descriptors: a FILE from this extension's C runtime can't be handed to
 * wpcap.dll, which may use another, but a Windows handle can
 */

static void ignore_invalid_parameter(const wchar_t *expression, const wchar_t *function, const wchar_t *file, unsigned int line, uintptr_t reserved) {
}

// a duplicate of fd's Windows handle, for pcap_hopen_offline() and
// pcap_dump_hopen(); libpcap closes the duplicate, which leaves the caller's
// descriptor open
static int dup_handle(int fd, intptr_t *copy) {
    _invalid_parameter_handler previous;
    intptr_t handle;
    HANDLE process;
    HANDLE duplicate;

    // the C runtime's default handler would end the process on a bad descriptor
    previous = _set_thread_local_invalid_parameter_handler(ignore_invalid_parameter);
    handle = _get_osfhandle(fd);
    _set_thread_local_invalid_parameter_handler(previous);

    // -2 means a standard stream with no console behind it
    if(-1 == handle || -2 == handle) {
        PyErr_SetString(PyPCAP_Error, strerror(EBADF));
        return -1;
    }

    process = GetCurrentProcess();
    if(!DuplicateHandle(process, (HANDLE)handle, process, &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
        PyErr_Format(PyPCAP_Error, "DuplicateHandle failed with error %lu", GetLastError());
        return -1;
    }

    *copy = (intptr_t)duplicate;
    return 0;
}

/*
 * Code that allows you to open a device by the name (e.g. Local Area Connection) instead of a GUID on Windows
 */

#define CANONICALPATH "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}"

// the connection name for the {GUID} part of an NPF device name, or NULL
static PyObject * device_to_canonical(const char *guid) {
    PyObject *name = NULL;
    HKEY hkey;
    char path[MAX_PATH];
    char value[MAX_PATH];
    DWORD len;

    snprintf(path, sizeof(path), CANONICALPATH "\\%s\\Connection", guid);

    if(ERROR_SUCCESS != RegOpenKeyEx(HKEY_LOCAL_MACHINE, path, 0, KEY_QUERY_VALUE, &hkey)) {
        return NULL;
    }

    len = sizeof(value);

    if(ERROR_SUCCESS == RegQueryValueEx(hkey, "Name", NULL, NULL, (LPBYTE)value, &len)) {
        name = PyUnicode_FromString(value);
    }

    RegCloseKey(hkey);

    return name;
}

// fills device (MAX_PATH) with the NPF device name for a connection name; -1 if there's none
static int canonical_to_device(const char *name, char *device) {
    HKEY base;
    HKEY connection;
    LONG hr;
    char path[MAX_PATH];
    char canon[MAX_PATH];
    char guid[MAX_PATH];
    int idx;
    DWORD len;

    if(ERROR_SUCCESS != RegOpenKeyEx(HKEY_LOCAL_MACHINE, CANONICALPATH, 0, KEY_ENUMERATE_SUB_KEYS, &base)) {
        return -1;
    }

    for(idx = 0; ; ++idx) {
        len = sizeof(guid);

        hr = RegEnumKeyEx(base, idx, guid, &len, NULL, NULL, NULL, NULL);
        if(ERROR_SUCCESS != hr && ERROR_MORE_DATA != hr) {
            break;
        }
        if(38 != len || '{' != guid[0]) {
            continue;
        }

        snprintf(path, sizeof(path), "%s\\Connection", guid);

        if(ERROR_SUCCESS != RegOpenKeyEx(base, path, 0, KEY_QUERY_VALUE, &connection)) {
            continue;
        }

        len = sizeof(canon);

        hr = RegQueryValueEx(connection, "Name", NULL, NULL, (LPBYTE)canon, &len);
        RegCloseKey(connection);
        if(ERROR_SUCCESS != hr) {
            continue;
        }

        if(!_stricmp(canon, name)) {
            snprintf(device, MAX_PATH, NPF_PREFIX "%s", guid);
            RegCloseKey(base);
            return 0;
        }
    }

    RegCloseKey(base);
    return -1;
}

#endif // WIN32
