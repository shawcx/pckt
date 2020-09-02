#include <arpa/inet.h>

#include "packetio.h"

static int        PacketIO_IP_Type_init    ( PacketIO_IP *, PyObject *, PyObject * );
static void       PacketIO_IP_Type_dealloc ( PacketIO_IP * );
static PyObject * PacketIO_IP_Type_str     ( PacketIO_IP * );

static PyObject * PacketIO_IP_pack   ( PacketIO_IP *, PyObject * );
static PyObject * PacketIO_IP_unpack ( PacketIO_IP *, PyObject * );

static PyMethodDef PacketIO_IP_methods[] = {
    { "pack",   (PyCFunction)PacketIO_IP_pack,   METH_NOARGS },
    { "unpack", (PyCFunction)PacketIO_IP_unpack, METH_O,     },
    { NULL }
};

static PyObject * PacketIO_IP_getter ( PacketIO_IP * self, void * param );
static int        PacketIO_IP_setter ( PacketIO_IP * self, PyObject * value, void * param );

#define PacketIO_IP_VERS   0
#define PacketIO_IP_HLEN   1
#define PacketIO_IP_TOS    2
#define PacketIO_IP_LEN    3
#define PacketIO_IP_ID     4
#define PacketIO_IP_FRAG   5
#define PacketIO_IP_TTL    6
#define PacketIO_IP_PROTO  7
#define PacketIO_IP_CRC    8
#define PacketIO_IP_SRC    9
#define PacketIO_IP_DST   10

static PyGetSetDef PacketIO_IP_getset[] = {
    { "vers",  (getter)PacketIO_IP_getter, (setter)PacketIO_IP_setter, "", (void*)PacketIO_IP_VERS  },
    { "hlen",  (getter)PacketIO_IP_getter, (setter)PacketIO_IP_setter, "", (void*)PacketIO_IP_HLEN  },
    { "tos",   (getter)PacketIO_IP_getter, (setter)PacketIO_IP_setter, "", (void*)PacketIO_IP_TOS   },
    { "len",   (getter)PacketIO_IP_getter, (setter)PacketIO_IP_setter, "", (void*)PacketIO_IP_LEN   },
    { "id",    (getter)PacketIO_IP_getter, (setter)PacketIO_IP_setter, "", (void*)PacketIO_IP_ID    },
    { "frag",  (getter)PacketIO_IP_getter, (setter)PacketIO_IP_setter, "", (void*)PacketIO_IP_FRAG  },
    { "ttl",   (getter)PacketIO_IP_getter, (setter)PacketIO_IP_setter, "", (void*)PacketIO_IP_TTL   },
    { "proto", (getter)PacketIO_IP_getter, (setter)PacketIO_IP_setter, "", (void*)PacketIO_IP_PROTO },
    { "crc",   (getter)PacketIO_IP_getter, (setter)PacketIO_IP_setter, "", (void*)PacketIO_IP_CRC   },
    { "src",   (getter)PacketIO_IP_getter, (setter)PacketIO_IP_setter, "", (void*)PacketIO_IP_SRC   },
    { "dst",   (getter)PacketIO_IP_getter, (setter)PacketIO_IP_setter, "", (void*)PacketIO_IP_DST   },
    { NULL }
};

static PyMemberDef PacketIO_IP_members[] = {
    { "layer4", T_OBJECT_EX, offsetof(PacketIO_IP, layer4), READONLY, "layer4"},
    { "tcp",    T_OBJECT_EX, offsetof(PacketIO_IP, layer4), READONLY, "TCP alias"},
    { "udp",    T_OBJECT_EX, offsetof(PacketIO_IP, layer4), READONLY, "UDP alias"},
    { "icmp",   T_OBJECT_EX, offsetof(PacketIO_IP, layer4), READONLY, "ICMP alias"},
    { NULL }
};

PyTypeObject PacketIO_IP_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "packetio.ip",
    sizeof(PacketIO_IP),
    0,    // itemsize
    (destructor)PacketIO_IP_Type_dealloc,
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
    (reprfunc)PacketIO_IP_Type_str,
    NULL, // getattro
    NULL, // setattro
    NULL, // as_buffer
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    "PacketIO.IP class",
    NULL, // traverse
    NULL, // clear
    NULL, // richcompare
    0,    // weaklistoffset
    NULL, // iter
    NULL, // iternext
    PacketIO_IP_methods,
    PacketIO_IP_members,
    PacketIO_IP_getset,
    NULL, // base
    NULL, // dict
    NULL, // descr_get
    NULL, // descr_set
    0,    // dictoffset
    (initproc)PacketIO_IP_Type_init,
    NULL, // alloc
    PyType_GenericNew
};

static int PacketIO_IP_Type_init(PacketIO_IP *self, PyObject *args, PyObject *kwds) {
    PyObject *bytes = NULL;
    int offset = 0;
    int ok;

    ok = PyArg_ParseTuple(args, "|Oi", &bytes, &offset);
    if(!ok) {
        PyErr_SetString(PyExc_TypeError, "invalid arguments");
        return -1;
    }

    self->layer4 = NULL;

    if(bytes) {
        if(!PyBytes_Check(bytes)) {
            PyErr_SetString(PyExc_TypeError, "expected bytes");
            return -1;
        }

        char *packet = PyBytes_AsString(bytes);
        memcpy(&self->ip, packet + offset, IP_HDR_LEN);

        if(self->ip.hlen != 5) {
            // TODO: additional IP header options
        }

        PyObject *layer4_type = NULL;

        switch(self->ip.proto) {
            case IP_TCP:
                layer4_type = (PyObject *)&PacketIO_TCP_Type;
                break;
            case IP_UDP:
                layer4_type = (PyObject *)&PacketIO_UDP_Type;
                break;
            case IP_ICMP:
                layer4_type = (PyObject *)&PacketIO_ICMP_Type;
                break;
        }

        if(layer4_type != NULL) {
            self->layer4 = PyObject_CallFunctionObjArgs(
                layer4_type,
                bytes,
                PyLong_FromLong(offset + (self->ip.hlen * 4)),
                NULL
                );
        }
    }

    return 0;
}

static void PacketIO_IP_Type_dealloc(PacketIO_IP *self) {
    if(NULL != self->layer4) {
        free(self->layer4);
        self->layer4 = NULL;
    }
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject * PacketIO_IP_Type_str(PacketIO_IP *self) {
    char src[32];
    char dst[32];

    strcpy(src, inet_ntoa(*((struct in_addr *)&self->ip.src)));
    strcpy(dst, inet_ntoa(*((struct in_addr *)&self->ip.dst)));

    return PyUnicode_FromFormat(
        "%s/%s %d %S",
        src,
        dst,
        self->ip.proto,
        self->layer4
        );
}

static PyObject * PacketIO_IP_getter(PacketIO_IP *self, void *param) {
    int field = (int)param;

    switch(field) {
        case PacketIO_IP_VERS:
            return PyLong_FromLong(self->ip.vers);
        case PacketIO_IP_HLEN:
            return PyLong_FromLong(self->ip.hlen);
        case PacketIO_IP_TOS:
            return PyLong_FromLong(self->ip.tos);
        case PacketIO_IP_LEN:
            return PyLong_FromLong(ntohs(self->ip.len));
        case PacketIO_IP_ID:
            return PyLong_FromLong(ntohs(self->ip.id));
        case PacketIO_IP_FRAG:
            return PyLong_FromLong(ntohs(self->ip.frag));
        case PacketIO_IP_TTL:
            return PyLong_FromLong(self->ip.ttl);
        case PacketIO_IP_PROTO:
            return PyLong_FromLong(self->ip.proto);
        case PacketIO_IP_CRC:
            return PyLong_FromLong(ntohs(self->ip.crc));
        case PacketIO_IP_SRC:
            return PyUnicode_FromString(inet_ntoa(*((struct in_addr *)&self->ip.src)));
        case PacketIO_IP_DST: {
            return PyUnicode_FromString(inet_ntoa(*((struct in_addr *)&self->ip.dst)));
        }
    }

    return NULL;
}

static int PacketIO_IP_setter(PacketIO_IP *self, PyObject *value, void *param) {
    int field = (int)param;

    switch(field) {
        case PacketIO_IP_VERS:
            self->ip.vers = PyLong_AsLong(value);
            break;
        case PacketIO_IP_HLEN:
            self->ip.hlen = PyLong_AsLong(value);
            break;
        case PacketIO_IP_TOS:
            self->ip.tos = PyLong_AsLong(value);
            break;
        case PacketIO_IP_LEN:
            self->ip.len = htons(PyLong_AsLong(value));
            break;
        case PacketIO_IP_ID:
            self->ip.id = htons(PyLong_AsLong(value));
            break;
        case PacketIO_IP_FRAG:
            self->ip.frag = htons(PyLong_AsLong(value));
            break;
        case PacketIO_IP_TTL:
            self->ip.ttl = PyLong_AsLong(value);
            break;
        case PacketIO_IP_PROTO:
            self->ip.proto = PyLong_AsLong(value);
            break;
        case PacketIO_IP_CRC:
            self->ip.crc = htons(PyLong_AsLong(value));
            break;
        case PacketIO_IP_SRC:
            {
                if(PyLong_Check(value)) {
                    self->ip.src = htonl(PyLong_AsLong(value));
                }
                else if(PyUnicode_Check(value)) {
                    inet_aton(PyUnicode_AsUTF8(value), (struct in_addr *)&self->ip.src);
                }
                else if(PyBytes_Check(value)) {
                    memcpy(&self->ip.src, PyBytes_AsString(value), 4);
                }
                else {
                    PyErr_SetString(PyExc_TypeError, "unknown type");
                    return -1;
                }
            }
            break;
        case PacketIO_IP_DST:
            {
                if(PyLong_Check(value)) {
                    self->ip.dst = htonl(PyLong_AsLong(value));
                }
                else if(PyUnicode_Check(value)) {
                    inet_aton(PyUnicode_AsUTF8(value), (struct in_addr *)&self->ip.dst);
                }
                else if(PyBytes_Check(value)) {
                    memcpy(&self->ip.dst, PyBytes_AsString(value), 4);
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

static PyObject * PacketIO_IP_pack(PacketIO_IP *self, PyObject *args) {
    Py_RETURN_NONE;
}

static PyObject * PacketIO_IP_unpack(PacketIO_IP *self, PyObject *args) {
    Py_RETURN_NONE;
}
