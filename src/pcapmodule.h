#ifndef __PYPCAP_H__
#define __PYPCAP_H__

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <structmember.h>

#include <pcap/pcap.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#ifdef WIN32
 #include <ws2tcpip.h>
#else
 #include <sys/socket.h>
 #include <netinet/in.h>
 #include <arpa/inet.h>
 #include <sys/ioctl.h>
 #include <net/if.h>
 #include <unistd.h>
 #ifdef __APPLE__
  #include <sys/sysctl.h>
  #include <net/route.h>
  #include <net/if_dl.h>
 #endif
 
 typedef unsigned char  BYTE;
 typedef unsigned short WORD;
 typedef unsigned int   DWORD;
 
#endif

// PCAP Module

PyMODINIT_FUNC PyInit_pcap(void);

static PyObject * PyPCAP_lib_version  ( PyObject * self );
static PyObject * PyPCAP_findalldevs  ( PyObject * self );
static PyObject * PyPCAP_mac          ( PyObject * self, PyObject * args );
static PyObject * PyPCAP_open_live    ( PyObject * self, PyObject * args );
static PyObject * PyPCAP_create       ( PyObject * self, PyObject * args );
static PyObject * PyPCAP_open_offline ( PyObject * self, PyObject * args );

// C callback that executes the Python callback
static void pcap_callback ( u_char * user, const struct pcap_pkthdr * hdr, const u_char * data);

#ifdef WIN32
// helper functions for nice device names on windows
#define NPF_PREFIX "\\Device\\NPF_"
static PyObject * device_to_canonical ( const char * guid );
static int        canonical_to_device ( const char * name, char * device );
#endif // WIN32

// Python Exception
static PyObject *PyPCAP_Error;

static PyMethodDef PyPCAP_module_methods[] = {
	{ "lib_version",  (PyCFunction)PyPCAP_lib_version,  METH_NOARGS,
	  "lib_version() => return pcap library version" },

	{ "findalldevs",  (PyCFunction)PyPCAP_findalldevs,  METH_NOARGS,
	  "findalldevs() => {device: {'mac', 'ip', 'netmask', 'broadcast'}}, with whichever are known" },

	{ "mac",          (PyCFunction)PyPCAP_mac,          METH_O,
	  "mac(device) => the interface's 6-byte hardware address" },

	{ "open_live",    (PyCFunction)PyPCAP_open_live,    METH_VARARGS,
	  "open_live(device, [snaplen=65535], [promisc=True], [timeout_ms=0]) => handle" },

	{ "create",       (PyCFunction)PyPCAP_create,       METH_O,
	  "create(device) => handle to configure with the set_*() methods, then activate()" },

	{ "open_offline", (PyCFunction)PyPCAP_open_offline, METH_O,
	  "open_offline(filename) => handle" },

	{ NULL }
};

// PCAP Object

typedef struct
{
	PyObject_HEAD
	pcap_t *pd;
	char errbuf[PCAP_ERRBUF_SIZE];
	PyObject *cb;
	PyObject *cbargs;
#ifdef WIN32
	char device[MAX_PATH];
#else
	char device[IFNAMSIZ];
#endif
} PyPCAP;

#define PCAPCTX if(NULL == self->pd) { PyErr_SetString(PyPCAP_Error, "invalid handle"); return NULL; }

void       PyPCAP_Type_dealloc ( PyPCAP * self );
PyObject * PyPCAP_Type_new     ( PyTypeObject * type, PyObject * args, PyObject * kwds );
int        PyPCAP_Type_init    ( PyPCAP * self, PyObject * args, PyObject * kwds );

static PyObject * PyPCAP_activate           ( PyPCAP * self );
static PyObject * PyPCAP_set_snaplen        ( PyPCAP * self, PyObject * args );
static PyObject * PyPCAP_set_promisc        ( PyPCAP * self, PyObject * args );
static PyObject * PyPCAP_set_timeout        ( PyPCAP * self, PyObject * args );
static PyObject * PyPCAP_set_immediate_mode ( PyPCAP * self, PyObject * args );
static PyObject * PyPCAP_geterr         ( PyPCAP * self );
static PyObject * PyPCAP_list_datalinks ( PyPCAP * self );
static PyObject * PyPCAP_datalink       ( PyPCAP * self );
static PyObject * PyPCAP_setdirection   ( PyPCAP * self, PyObject * args );
static PyObject * PyPCAP_setnonblock    ( PyPCAP * self, PyObject * args );
static PyObject * PyPCAP_getnonblock    ( PyPCAP * self );
static PyObject * PyPCAP_setfilter      ( PyPCAP * self, PyObject * args );
static PyObject * PyPCAP_loop           ( PyPCAP * self, PyObject * args );
static PyObject * PyPCAP_breakloop      ( PyPCAP * self );
static PyObject * PyPCAP_next_ex        ( PyPCAP * self );
#ifndef WIN32
static PyObject * PyPCAP_fileno         ( PyPCAP * self );
#endif
#ifndef WIN32
static PyObject * PyPCAP_inject         ( PyPCAP * self, PyObject * args );
#endif
static PyObject * PyPCAP_sendpacket     ( PyPCAP * self, PyObject * args );
static PyObject * PyPCAP_snapshot       ( PyPCAP * self );
static PyObject * PyPCAP_close          ( PyPCAP * self );
static PyObject * PyPCAP_stats          ( PyPCAP * self );
#ifdef WIN32
//static PyObject * PyPCAP_stats_ex       ( PyPCAP * self );
static PyObject * PyPCAP_getevent       ( PyPCAP * self );
#endif // WIN32

static PyMethodDef PyPCAP_Type_methods[] = {
	{ "activate",           (PyCFunction)PyPCAP_activate,           METH_NOARGS,
	  "activate() => None, or a warning string; starts a handle from create()" },
	{ "set_snaplen",        (PyCFunction)PyPCAP_set_snaplen,        METH_O,
	  "set_snaplen(int), before activate()" },
	{ "set_promisc",        (PyCFunction)PyPCAP_set_promisc,        METH_O,
	  "set_promisc(bool), before activate()" },
	{ "set_timeout",        (PyCFunction)PyPCAP_set_timeout,        METH_O,
	  "set_timeout(ms), before activate()" },
	{ "set_immediate_mode", (PyCFunction)PyPCAP_set_immediate_mode, METH_O,
	  "set_immediate_mode(bool), before activate(): deliver packets as they arrive rather than buffering" },
	{ "geterr",         (PyCFunction)PyPCAP_geterr,         METH_NOARGS,
	  "geterr() => libpcap's last error message for this handle" },
	{ "list_datalinks", (PyCFunction)PyPCAP_list_datalinks, METH_NOARGS,
	  "list_datalinks() => [(dlt, name, description), ...]" },
	{ "datalink",       (PyCFunction)PyPCAP_datalink,       METH_NOARGS,
	  "datalink() => (dlt, name, description)" },
	{ "setdirection",   (PyCFunction)PyPCAP_setdirection,   METH_VARARGS,
	  "setdirection(D_IN | D_OUT | D_INOUT)" },
	{ "setnonblock",    (PyCFunction)PyPCAP_setnonblock,    METH_O,
	  "setnonblock(bool)" },
	{ "getnonblock",    (PyCFunction)PyPCAP_getnonblock,    METH_NOARGS,
	  "getnonblock() => bool" },
	{ "setfilter",      (PyCFunction)PyPCAP_setfilter,      METH_O,
	  "setfilter(bpf expression)" },
	{ "loop",           (PyCFunction)PyPCAP_loop,           METH_VARARGS,
	  "loop(callback, [count=-1], *extra) calls callback(data, ts, wirelen, *extra) per packet; "
	  "stops after count packets, on breakloop() or when the callback raises. "
	  "Signals (Ctrl-C) are only seen when a packet arrives; see pckt.capture.packets()" },
	{ "breakloop",      (PyCFunction)PyPCAP_breakloop,      METH_NOARGS,
	  "breakloop() stops loop(), including from another thread" },
	{ "next",           (PyCFunction)PyPCAP_next_ex,        METH_NOARGS,
	  "next() => (data, ts, wirelen), or None when no packet is available yet (timeout or non-blocking); "
	  "raises EOFError at the end of a file" },
#ifndef WIN32
	{ "fileno",         (PyCFunction)PyPCAP_fileno,         METH_NOARGS,
	  "fileno() => descriptor to select() on; use with setnonblock(True). "
	  "On Linux the read timeout is not honored while the interface is idle." },
#endif
#ifndef WIN32
	{ "inject",         (PyCFunction)PyPCAP_inject,         METH_O,
	  "inject(bytes) => bytes sent" },
#endif
	{ "sendpacket",     (PyCFunction)PyPCAP_sendpacket,     METH_O,
	  "sendpacket(bytes)" },
	{ "snapshot",       (PyCFunction)PyPCAP_snapshot,       METH_NOARGS,
	  "snapshot() => snaplen" },
	{ "close",          (PyCFunction)PyPCAP_close,          METH_NOARGS,
	  "close()" },
	{ "stats",          (PyCFunction)PyPCAP_stats,          METH_NOARGS,
	  "stats() => (received, dropped, dropped by interface)" },
#ifdef WIN32
//	{ "stats_ex",       (PyCFunction)PyPCAP_stats_ex,       METH_NOARGS  },
	{ "getevent",       (PyCFunction)PyPCAP_getevent,       METH_NOARGS  },
#endif // WIN32
	{ NULL }
};

static PyTypeObject PyPCAP_Type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"pckt.pcap.Handle",                // name
	sizeof(PyPCAP),                    // basicsize
	0,                                 // itemsize
	(destructor)PyPCAP_Type_dealloc,   // dealloc
	0,                                 // print
	0,                                 // getattr
	0,                                 // setattr
	0,                                 // compare
	0,                                 // repr
	0,                                 // as_number
	0,                                 // as_sequence
	0,                                 // as_mapping
	0,                                 // hash
	0,                                 // call
	0,                                 // str
	0,                                 // getattro
	0,                                 // setattro
	0,                                 // as_buffer
	Py_TPFLAGS_DEFAULT,
	"pcap capture handle",             // doc
	0,                                 // traverse
	0,                                 // clear
	0,                                 // richcompare
	0,                                 // weaklistoffset
	0,                                 // iter
	0,                                 // iternext
	PyPCAP_Type_methods,               // methods
	0,                                 // members
	0,                                 // getset
	0,                                 // base
	0,                                 // dict
	0,                                 // descr_get
	0,                                 // descr_set
	0,                                 // dictoffset
	(initproc)PyPCAP_Type_init,        // init
	0,                                 // alloc
	PyPCAP_Type_new,                   // new
};

#endif // __PYPCAP_H__
