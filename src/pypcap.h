#ifndef __PYPCAP_H__
#define __PYPCAP_H__

#define PY_SSIZE_T_CLEAN

#include <Python.h>
#include <pcap.h>
#include <signal.h>

#if defined(_MSC_VER)
 typedef SSIZE_T ssize_t;
#endif

#ifndef WIN32
 #include <arpa/inet.h>
 #include <net/if.h>
#ifdef MACOS
 #include <net/if_dl.h>
 #include <sys/sysctl.h>
#endif
 #include <netinet/in.h>
 #include <sys/ioctl.h>
 #include <sys/socket.h>
 #include <sys/types.h>
 #include <errno.h>
#endif

#define  DEFAULT_SNAPLEN  65535
#define  DEFAULT_PROMISC  1
#define  DEFAULT_TO_MS    100

#define  DOC_MOD  "Python wrapper for libpcap"

#ifndef FALSE
#define FALSE 0
#endif

PyMODINIT_FUNC PyInit_pcap(void);

typedef struct {
    PyObject_HEAD
    pcap_t *pd;
} PyPCAP;

static PyObject * pypcap_version   (PyObject * self);
static PyObject * pypcap_find      (PyObject * self);
static PyObject * pypcap_mac       (PyObject * self, PyObject * adapter);

static PyPCAP * pypcap_open_live (PyObject * self, PyObject * arguments);
static PyPCAP * pypcap_open_file (PyObject * self, PyObject * filename);
static PyPCAP * pypcap_create    (PyObject * self, PyObject * adapter);

static PyMethodDef PyPCAP_methods[] = {
    { "version",   (PyCFunction)pypcap_version,   METH_NOARGS,  "return the version"                },
    { "find",      (PyCFunction)pypcap_find,      METH_NOARGS,  "find suitable devices in a system" },
    { "mac",       (PyCFunction)pypcap_mac,       METH_O,       "MAC address of an adapter"       },
    { "open_live", (PyCFunction)pypcap_open_live, METH_VARARGS, "open an adapter"                 },
    //{ "open_dead", (PyCFunction)pypcap_open_dead, METH_VARARGS, "open an adapter"                 },
    { "open_file", (PyCFunction)pypcap_open_file, METH_O,       "open a file"                       },
    { "create",    (PyCFunction)pypcap_create,    METH_O,       "create a live capture handle"      },
    { NULL }
};

static PyModuleDef PyPCAP_module = {
    PyModuleDef_HEAD_INIT,
    .m_name    = "pypcap",
    .m_doc     = NULL,
    .m_size    = -1,
    .m_methods = PyPCAP_methods
};


static int  pypcap_init   (PyPCAP*, PyObject*, PyObject*);
static void pypcap_dealloc(PyPCAP *self);

static PyObject * pypcap_activate       (PyPCAP *self);
static PyObject * pypcap_close          (PyPCAP *self);
static PyObject * pypcap_stats          (PyPCAP *self);
static PyObject * pypcap_geterr         (PyPCAP *self);
static PyObject * pypcap_list_datalinks (PyPCAP *self);
static PyObject * pypcap_datalink       (PyPCAP *self);
static PyObject * pypcap_setnonblock    (PyPCAP *self, PyObject *blocking);
static PyObject * pypcap_getnonblock    (PyPCAP *self);
static PyObject * pypcap_setdirection   (PyPCAP *self, PyObject *direction);
static PyObject * pypcap_loop           (PyPCAP *self, PyObject *arguments);
static PyObject * pypcap_breakloop      (PyPCAP *self);
static PyObject * pypcap_next           (PyPCAP *self);
static PyObject * pypcap_fileno         (PyPCAP *self);
static PyObject * pypcap_inject         (PyPCAP *self, PyObject *packet);
#ifdef WIN32
static PyObject * pypcap_getevent       (PyPCAP *self);
#endif // WIN32

static PyMethodDef PyPCAP_Type_methods[] = {
    { "activate",      (PyCFunction)pypcap_activate,       METH_NOARGS,  "activate an adapter"              },
    { "close",         (PyCFunction)pypcap_close,          METH_NOARGS,  "close an adapter"                 },
    { "stats",         (PyCFunction)pypcap_stats,          METH_NOARGS,  "get stats from a sessions"          },
    { "geterr",        (PyCFunction)pypcap_geterr,         METH_NOARGS,  "print the last error"               },
    { "list_datalinks",(PyCFunction)pypcap_list_datalinks, METH_NOARGS,  "return list of supported datalinks" },
    { "datalink",      (PyCFunction)pypcap_datalink,       METH_NOARGS,  "get datalink"                       },
    { "setnonblock",   (PyCFunction)pypcap_setnonblock,    METH_O,       "set blocking or non-blocking"       },
    { "getnonblock",   (PyCFunction)pypcap_getnonblock,    METH_NOARGS,  "get blocking state"                 },
    { "setdirection",  (PyCFunction)pypcap_setdirection,   METH_O,       "set the direction of a capture"     },
    { "loop",          (PyCFunction)pypcap_loop,           METH_VARARGS, "call a callback function on packet" },
    { "breakloop",     (PyCFunction)pypcap_breakloop,      METH_NOARGS,  "cancel the callback function"       },
    { "next",          (PyCFunction)pypcap_next,           METH_NOARGS,  "read the next packet"               },
    { "fileno",        (PyCFunction)pypcap_fileno,         METH_NOARGS,  "fetch file descriptor"              },
    { "inject",        (PyCFunction)pypcap_inject,         METH_O,       "send a packet on the adapter"     },
#ifdef WIN32
    { "getevent",      (PyCFunction)pypcap_getevent,       METH_NOARGS,  "get an event handle"                },
#endif // WIN32
    { NULL }
};

static PyTypeObject PyPCAP_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name      = "pypcap",
    .tp_doc       = "pypcap Class",
    .tp_basicsize = sizeof(PyPCAP),
    .tp_new       = PyType_GenericNew,
    .tp_init      = (initproc)pypcap_init,
    .tp_dealloc   = (destructor)pypcap_dealloc,
    .tp_flags     = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    .tp_methods   = PyPCAP_Type_methods,
};

#ifdef WIN32
static int get_canonical(char *guid, char *name);
static int get_guid(char *name, char *guid);
#endif // WIN32

#endif // __PYPCAP_H__
