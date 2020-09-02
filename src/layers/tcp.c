#include "packetio.h"

static int        PacketIO_TCP_Type_init    ( PacketIO_TCP *, PyObject *, PyObject * );
static void       PacketIO_TCP_Type_dealloc ( PacketIO_TCP * );
static PyObject * PacketIO_TCP_Type_str     ( PacketIO_TCP * );

static PyObject * PacketIO_TCP_pack   ( PacketIO_TCP *, PyObject * );
static PyObject * PacketIO_TCP_unpack ( PacketIO_TCP *, PyObject * );

static PyMethodDef PacketIO_TCP_methods[] = {
    { "pack",   (PyCFunction)PacketIO_TCP_pack,   METH_NOARGS },
    { "unpack", (PyCFunction)PacketIO_TCP_unpack, METH_O,     },
    { NULL }
};

static PyObject * PacketIO_TCP_getter ( PacketIO_TCP * self, void * param );
static int        PacketIO_TCP_setter ( PacketIO_TCP * self, PyObject * value, void * param );

#define PacketIO_TCP_SRC    0
#define PacketIO_TCP_DST    1
#define PacketIO_TCP_SEQ    2
#define PacketIO_TCP_ACK    3
#define PacketIO_TCP_HLEN   4
#define PacketIO_TCP_FLAGS  5
#define PacketIO_TCP_WINDOW 6
#define PacketIO_TCP_CRC    7
#define PacketIO_TCP_URGENT 8

static PyGetSetDef PacketIO_TCP_getset[] = {
    { "src",    (getter)PacketIO_TCP_getter, (setter)PacketIO_TCP_setter, "", (void*)PacketIO_TCP_SRC    },
    { "dst",    (getter)PacketIO_TCP_getter, (setter)PacketIO_TCP_setter, "", (void*)PacketIO_TCP_DST    },
    { "seq",    (getter)PacketIO_TCP_getter, (setter)PacketIO_TCP_setter, "", (void*)PacketIO_TCP_SEQ    },
    { "ack",    (getter)PacketIO_TCP_getter, (setter)PacketIO_TCP_setter, "", (void*)PacketIO_TCP_ACK    },
    { "hlen",   (getter)PacketIO_TCP_getter, (setter)PacketIO_TCP_setter, "", (void*)PacketIO_TCP_HLEN   },
    { "flags",  (getter)PacketIO_TCP_getter, (setter)PacketIO_TCP_setter, "", (void*)PacketIO_TCP_FLAGS  },
    { "window", (getter)PacketIO_TCP_getter, (setter)PacketIO_TCP_setter, "", (void*)PacketIO_TCP_WINDOW },
    { "crc",    (getter)PacketIO_TCP_getter, (setter)PacketIO_TCP_setter, "", (void*)PacketIO_TCP_CRC    },
    { "urgent", (getter)PacketIO_TCP_getter, (setter)PacketIO_TCP_setter, "", (void*)PacketIO_TCP_URGENT },
    { NULL }
};

static PyMemberDef PacketIO_TCP_members[] = {
    { "data", T_OBJECT_EX, offsetof(PacketIO_TCP, data), READONLY, "data"},
    { NULL }
};

PyTypeObject PacketIO_TCP_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "packetio.tcp",
    sizeof(PacketIO_TCP),
    0,    // itemsize
    (destructor)PacketIO_TCP_Type_dealloc,
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
    (reprfunc)PacketIO_TCP_Type_str,
    NULL, // getattro
    NULL, // setattro
    NULL, // as_buffer
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    "PacketIO.TCP class",
    NULL, // traverse
    NULL, // clear
    NULL, // richcompare
    0,    // weaklistoffset
    NULL, // iter
    NULL, // iternext
    PacketIO_TCP_methods,
    PacketIO_TCP_members,
    PacketIO_TCP_getset,
    NULL, // base
    NULL, // dict
    NULL, // descr_get
    NULL, // descr_set
    0,    // dictoffset
    (initproc)PacketIO_TCP_Type_init,
    NULL, // alloc
    PyType_GenericNew
};


static int PacketIO_TCP_Type_init(PacketIO_TCP *self, PyObject *args, PyObject *kwds) {
    PyObject *bytes = NULL;
    int offset = 0;
    int ok;

    ok = PyArg_ParseTuple(args, "|Oi", &bytes, &offset);
    if(!ok) {
        PyErr_SetString(PyExc_TypeError, "invalid arguments");
        return -1;
    }

    self->data = NULL;

    if(bytes) {
        if(!PyBytes_Check(bytes)) {
            PyErr_SetString(PyExc_TypeError, "expected bytes");
            return -1;
        }
        char *packet = PyBytes_AsString(bytes);
        memcpy(&self->tcp, packet + offset, TCP_HDR_LEN);
    }

    return 0;
}

static void PacketIO_TCP_Type_dealloc(PacketIO_TCP *self) {
    if(NULL != self->data) {
        //free(self->data);
        self->data = NULL;
    }
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject * PacketIO_TCP_Type_str(PacketIO_TCP *self) {
    return PyUnicode_FromFormat(
        "%d/%d",
        htons(self->tcp.src),
        htons(self->tcp.dst)
        );
}

static PyObject * PacketIO_TCP_getter(PacketIO_TCP *self, void *param) {
    int field = (int)param;

    switch(field) {
        case PacketIO_TCP_SRC:
            return PyLong_FromLong(ntohs(self->tcp.src));
        case PacketIO_TCP_DST:
            return PyLong_FromLong(ntohs(self->tcp.dst));
        case PacketIO_TCP_SEQ:
            return PyLong_FromLong(ntohl(self->tcp.seq));
        case PacketIO_TCP_ACK:
            return PyLong_FromLong(ntohl(self->tcp.ack));
        case PacketIO_TCP_HLEN:
            return PyLong_FromLong(self->tcp.hlen);
        case PacketIO_TCP_FLAGS:
            return PyLong_FromLong(self->tcp.flags);
        case PacketIO_TCP_WINDOW:
            return PyLong_FromLong(ntohs(self->tcp.window));
        case PacketIO_TCP_CRC:
            return PyLong_FromLong(ntohs(self->tcp.crc));
        case PacketIO_TCP_URGENT:
            return PyLong_FromLong(ntohs(self->tcp.urgent));
    }
    return NULL;
}

static int PacketIO_TCP_setter(PacketIO_TCP *self, PyObject *value, void *param) {
    int field = (int)param;

    switch(field) {
        case PacketIO_TCP_SRC:
            self->tcp.src = htons(PyLong_AsLong(value));
            break;
        case PacketIO_TCP_DST:
            self->tcp.dst = htons(PyLong_AsLong(value));
            break;
        case PacketIO_TCP_SEQ:
            self->tcp.seq = htonl(PyLong_AsLong(value));
            break;
        case PacketIO_TCP_ACK:
            self->tcp.ack = htonl(PyLong_AsLong(value));
            break;
        case PacketIO_TCP_HLEN:
            self->tcp.hlen = PyLong_AsLong(value);
            break;
        case PacketIO_TCP_FLAGS:
            self->tcp.flags = PyLong_AsLong(value);
            break;
        case PacketIO_TCP_WINDOW:
            self->tcp.window = htons(PyLong_AsLong(value));
            break;
        case PacketIO_TCP_CRC:
            self->tcp.crc = htons(PyLong_AsLong(value));
            break;
        case PacketIO_TCP_URGENT:
            self->tcp.urgent = htons(PyLong_AsLong(value));
            break;
    }

    return 0;
}

static PyObject * PacketIO_TCP_pack(PacketIO_TCP *self, PyObject *args) {

    Py_RETURN_NONE;
}

static PyObject * PacketIO_TCP_unpack(PacketIO_TCP *self, PyObject *args) {

    Py_RETURN_NONE;
}
