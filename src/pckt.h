#ifndef __PYPCAP_H__
#define __PYPCAP_H__

#include <Python.h>
#include <structmember.h>

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>

typedef unsigned char  BYTE;
typedef unsigned short WORD;
typedef unsigned int   DWORD;
#endif

// PCAP Module

PyMODINIT_FUNC PyInit__pckt(void);

static PyObject * PyPCAP_findalldevs  ( PyObject * self );

#ifdef WIN32
// helper functions for nice device names on windows
PyObject * device_to_canonical ( char * guid );
#endif // WIN32

// compute crc on outbound packets
void crc ( BYTE * pkt );

// Python Exception
static PyObject *Pckt_Error;

static PyMethodDef PyPCAP_module_methods[] = {
	{ "lib_version",  (PyCFunction)PyPCAP_lib_version,  METH_NOARGS,
	  "lib_version() => return pcap library version" },

	{ "findalldevs",  (PyCFunction)PyPCAP_findalldevs,  METH_NOARGS,
	  "findalldevs() => return dictionary of interfaces" },

	{ "create",       (PyCFunction)PyPCAP_create,       METH_O,
	  "create(device) => pcap object" },

	{ "open_live",    (PyCFunction)PyPCAP_open_live,    METH_VARARGS,
	  "open_live(device, [capture length], [promisc], [read timeout]) => pcap object" },

	{ "open_offline", (PyCFunction)PyPCAP_open_offline, METH_O,
	  "open_offline(filename) => pcap object" },

	{ NULL }
};

// PCAP Object

typedef struct {
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

#define PCAPCTX if(NULL == self->pd) { PyErr_SetString(Pckt_Error, "invalid handle"); return NULL; }

void       PyPCAP_Type_dealloc ( PyPCAP * self );
PyObject * PyPCAP_Type_new     ( PyTypeObject * type, PyObject * args, PyObject * kwds );
int        PyPCAP_Type_init    ( PyPCAP * self, PyObject * args, PyObject * kwds );

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
	{ "list_datalinks", (PyCFunction)PyPCAP_list_datalinks, METH_NOARGS  },
	{ "datalink",       (PyCFunction)PyPCAP_datalink,       METH_NOARGS  },
	{ "setdirection",   (PyCFunction)PyPCAP_setdirection,   METH_VARARGS },
	{ "setnonblock",    (PyCFunction)PyPCAP_setnonblock,    METH_O       },
	{ "getnonblock",    (PyCFunction)PyPCAP_getnonblock,    METH_NOARGS  },
	{ "setfilter",      (PyCFunction)PyPCAP_setfilter,      METH_O       },
	{ "loop",           (PyCFunction)PyPCAP_loop,           METH_VARARGS },
	{ "breakloop",      (PyCFunction)PyPCAP_breakloop,      METH_NOARGS  },
	{ "next",           (PyCFunction)PyPCAP_next_ex,        METH_NOARGS  },
	{ "next_ex",        (PyCFunction)PyPCAP_next_ex,        METH_NOARGS  },
#ifndef WIN32
	{ "inject",         (PyCFunction)PyPCAP_inject,         METH_O       },
#endif
	{ "sendpacket",     (PyCFunction)PyPCAP_sendpacket,     METH_O       },
	{ "snapshot",       (PyCFunction)PyPCAP_snapshot,       METH_NOARGS  },
	{ "close",          (PyCFunction)PyPCAP_close,          METH_NOARGS  },
	{ "stats",          (PyCFunction)PyPCAP_stats,          METH_NOARGS  },
#ifdef WIN32
//	{ "stats_ex",       (PyCFunction)PyPCAP_stats_ex,       METH_NOARGS  },
	{ "getevent",       (PyCFunction)PyPCAP_getevent,       METH_NOARGS  },
#endif // WIN32
	{ NULL }
};

static PyTypeObject PyPCAP_Type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"pypcap.pypcap",                   // name
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
	"pcap class",                      // doc
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
