#include <arpa/inet.h>

#include "packetio.h"

static int        PacketIO_ARP_Type_init    ( PacketIO_ARP *, PyObject *, PyObject * );
static void       PacketIO_ARP_Type_dealloc ( PacketIO_ARP * );
static PyObject * PacketIO_ARP_Type_str     ( PacketIO_ARP * );

static PyObject * PacketIO_ARP_pack   ( PacketIO_ARP *, PyObject * );
static PyObject * PacketIO_ARP_unpack ( PacketIO_ARP *, PyObject * );

static PyMethodDef PacketIO_ARP_methods[] = {
    { "pack",   (PyCFunction)PacketIO_ARP_pack,   METH_NOARGS },
    { "unpack", (PyCFunction)PacketIO_ARP_unpack, METH_O,     },
    { NULL }
};

static PyObject * PacketIO_ARP_getter ( PacketIO_ARP * self, void * param );
static int        PacketIO_ARP_setter ( PacketIO_ARP * self, PyObject * value, void * param );

#define PacketIO_ARP_HW        0
#define PacketIO_ARP_PROTO     1
#define PacketIO_ARP_HWSIZE    2
#define PacketIO_ARP_PROTOSIZE 3
#define PacketIO_ARP_OP        4
#define PacketIO_ARP_SRC_MAC   5
#define PacketIO_ARP_SRC_IP    6
#define PacketIO_ARP_DST_MAC   7
#define PacketIO_ARP_DST_IP    8

static PyGetSetDef PacketIO_ARP_getset[] = {
    { "hw",        (getter)PacketIO_ARP_getter, (setter)PacketIO_ARP_setter, "", (void*)PacketIO_ARP_HW        },
    { "proto",     (getter)PacketIO_ARP_getter, (setter)PacketIO_ARP_setter, "", (void*)PacketIO_ARP_PROTO     },
    { "hwsize",    (getter)PacketIO_ARP_getter, (setter)PacketIO_ARP_setter, "", (void*)PacketIO_ARP_HWSIZE    },
    { "protosize", (getter)PacketIO_ARP_getter, (setter)PacketIO_ARP_setter, "", (void*)PacketIO_ARP_PROTOSIZE },
    { "op",        (getter)PacketIO_ARP_getter, (setter)PacketIO_ARP_setter, "", (void*)PacketIO_ARP_OP        },
    { "src_mac",   (getter)PacketIO_ARP_getter, (setter)PacketIO_ARP_setter, "", (void*)PacketIO_ARP_SRC_MAC   },
    { "src_ip",    (getter)PacketIO_ARP_getter, (setter)PacketIO_ARP_setter, "", (void*)PacketIO_ARP_SRC_IP    },
    { "dst_mac",   (getter)PacketIO_ARP_getter, (setter)PacketIO_ARP_setter, "", (void*)PacketIO_ARP_DST_MAC   },
    { "dst_ip",    (getter)PacketIO_ARP_getter, (setter)PacketIO_ARP_setter, "", (void*)PacketIO_ARP_DST_IP    },
    { NULL }
};

PyTypeObject PacketIO_ARP_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "packetio.arp",
    sizeof(PacketIO_ARP),
    0,    // itemsize
    (destructor)PacketIO_ARP_Type_dealloc,
    NULL, // print
    NULL, // getattr
    NULL, // setattr
    NULL, // reserved
    NULL, // repr
    NULL, // as_number
    NULL, // as_sequence
    NULL, // as_mapping
    NULL, // hash
    NULL, // call
    (reprfunc)PacketIO_ARP_Type_str,
    NULL, // getattro
    NULL, // setattro
    NULL, // as_buffer
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    "PacketIO.ARP class",
    NULL, // traverse
    NULL, // clear
    NULL, // richcompare
    0,    // weaklistoffset
    NULL, // iter
    NULL, // iternext
    PacketIO_ARP_methods,
    NULL, // members
    PacketIO_ARP_getset,
    NULL, // base
    NULL, // dict
    NULL, // descr_get
    NULL, // descr_set
    0,    // dictoffset
    (initproc)PacketIO_ARP_Type_init,
    NULL, // alloc
    PyType_GenericNew
};

static int PacketIO_ARP_Type_init(PacketIO_ARP *self, PyObject *args, PyObject *kwds) {
    PyObject *bytes = NULL;
    int offset = 0;
    int ok;

    ok = PyArg_ParseTuple(args, "|Oi", &bytes, &offset);
    if(!ok) {
        PyErr_SetString(PyExc_TypeError, "invalid arguments");
        return -1;
    }

    if(bytes) {
        if(!PyBytes_Check(bytes)) {
            PyErr_SetString(PyExc_TypeError, "expected bytes");
            return -1;
        }
        memcpy(&self->arp, PyBytes_AsString(bytes) + offset, ARP_HDR_LEN);
        // TODO: additional ARP header options
    }

    return 0;
}

static void PacketIO_ARP_Type_dealloc(PacketIO_ARP *self) {
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject * PacketIO_ARP_Type_str(PacketIO_ARP *self) {
    return PyUnicode_FromFormat(
        "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x %d.%d.%d.%d / %.2x:%.2x:%.2x:%.2x:%.2x:%.2x %u.%u.%u.%u %.4x",
        self->arp.src_mac[0],
        self->arp.src_mac[1],
        self->arp.src_mac[2],
        self->arp.src_mac[3],
        self->arp.src_mac[4],
        self->arp.src_mac[5],
        self->arp.src_ip[0],
        self->arp.src_ip[1],
        self->arp.src_ip[2],
        self->arp.src_ip[3],
        self->arp.dst_mac[0],
        self->arp.dst_mac[1],
        self->arp.dst_mac[2],
        self->arp.dst_mac[3],
        self->arp.dst_mac[4],
        self->arp.dst_mac[5],
        self->arp.dst_ip[0],
        self->arp.dst_ip[1],
        self->arp.dst_ip[2],
        self->arp.dst_ip[3],
        ntohs(self->arp.proto)
        );

}

static PyObject * PacketIO_ARP_getter(PacketIO_ARP *self, void *param) {
    int field = (int)param;

    switch(field) {
        case PacketIO_ARP_HW:
            return PyLong_FromLong(ntohs(self->arp.hw));
        case PacketIO_ARP_PROTO:
            return PyLong_FromLong(ntohs(self->arp.proto));
        case PacketIO_ARP_HWSIZE:
            return PyLong_FromLong(self->arp.hwsize);
        case PacketIO_ARP_PROTOSIZE:
            return PyLong_FromLong(self->arp.protosize);
        case PacketIO_ARP_OP:
            return PyLong_FromLong(ntohs(self->arp.op));
        case PacketIO_ARP_SRC_MAC:
            return PyBytes_FromStringAndSize((char *)self->arp.src_mac, ETHERNET_ADDR_LEN);
        case PacketIO_ARP_SRC_IP:
            return PyUnicode_FromString(inet_ntoa(*((struct in_addr *)&self->arp.src_ip)));
        case PacketIO_ARP_DST_MAC:
            return PyBytes_FromStringAndSize((char *)self->arp.dst_mac, ETHERNET_ADDR_LEN);
        case PacketIO_ARP_DST_IP:
            return PyUnicode_FromString(inet_ntoa(*((struct in_addr *)&self->arp.dst_ip)));
    }

    return NULL;
}

static int PacketIO_ARP_setter(PacketIO_ARP *self, PyObject *value, void *param) {
    int field = (int)param;

    switch(field) {
        case PacketIO_ARP_HW:
            self->arp.hw = htons(PyLong_AsLong(value));
            break;
        case PacketIO_ARP_PROTO:
            self->arp.proto = htons(PyLong_AsLong(value));
            break;
        case PacketIO_ARP_HWSIZE:
            self->arp.hwsize = PyLong_AsLong(value);
            break;
        case PacketIO_ARP_PROTOSIZE:
            self->arp.protosize = PyLong_AsLong(value);
            break;
        case PacketIO_ARP_OP:
            self->arp.op = PyLong_AsLong(value);
            break;
        case PacketIO_ARP_SRC_MAC:
            {
                if(PyBytes_Check(value)) {
                    memcpy(self->arp.src_mac, PyBytes_AsString(value), ETHERNET_ADDR_LEN);
                }
                else if(PyUnicode_Check(value)) {
                    sscanf(PyUnicode_AsUTF8(value), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                        &self->arp.src_mac[0],
                        &self->arp.src_mac[1],
                        &self->arp.src_mac[2],
                        &self->arp.src_mac[3],
                        &self->arp.src_mac[4],
                        &self->arp.src_mac[5]
                        );
                }
                else {
                    return -1;
                }
            }
            break;
        case PacketIO_ARP_SRC_IP:
            {
                if(PyLong_Check(value)) {
                    uint32_t src_ip = htonl(PyLong_AsLong(value));
                    memcpy(self->arp.src_ip, &src_ip, 4);
                }
                else if(PyUnicode_Check(value)) {
                    sscanf(PyUnicode_AsUTF8(value), "%hhu.%hhu.%hhu.%hhu",
                        &self->arp.dst_ip[0],
                        &self->arp.dst_ip[1],
                        &self->arp.dst_ip[2],
                        &self->arp.dst_ip[3]
                        );
                }
                else if(PyBytes_Check(value)) {
                    memcpy(&self->arp.src_ip, PyBytes_AsString(value), 4);
                }
                else {
                    PyErr_SetString(PyExc_TypeError, "unknown type");
                    return -1;
                }
            }
            break;
        case PacketIO_ARP_DST_MAC:
            {
                if(PyBytes_Check(value)) {
                    memcpy(self->arp.dst_mac, PyBytes_AsString(value), ETHERNET_ADDR_LEN);
                }
                else if(PyUnicode_Check(value)) {
                    sscanf(PyUnicode_AsUTF8(value), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                        &self->arp.dst_mac[0],
                        &self->arp.dst_mac[1],
                        &self->arp.dst_mac[2],
                        &self->arp.dst_mac[3],
                        &self->arp.dst_mac[4],
                        &self->arp.dst_mac[5]
                        );
                }
                else {
                    return -1;
                }
            }
            break;
        case PacketIO_ARP_DST_IP:
            {
                if(PyLong_Check(value)) {
                    uint32_t dst_ip = htonl(PyLong_AsLong(value));
                    memcpy(self->arp.dst_ip, &dst_ip, 4);
                }
                else if(PyUnicode_Check(value)) {
                    sscanf(PyUnicode_AsUTF8(value), "%hhu.%hhu.%hhu.%hhu",
                        &self->arp.dst_ip[0],
                        &self->arp.dst_ip[1],
                        &self->arp.dst_ip[2],
                        &self->arp.dst_ip[3]
                        );
                }
                else if(PyBytes_Check(value)) {
                    memcpy(&self->arp.dst_ip, PyBytes_AsString(value), 4);
                }
                else {
                    PyErr_SetString(PyExc_TypeError, "unknown type");
                    return -1;
                }
            }
            break;
    }

    return 0;
}

static PyObject * PacketIO_ARP_pack(PacketIO_ARP *self, PyObject *args) {
    Py_RETURN_NONE;
}

static PyObject * PacketIO_ARP_unpack(PacketIO_ARP *self, PyObject *args) {
    Py_RETURN_NONE;
}
