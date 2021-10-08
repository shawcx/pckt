#include "packetio.h"

static int        PacketIO_UDP_Type_init    ( PacketIO_UDP *, PyObject *, PyObject * );
static void       PacketIO_UDP_Type_dealloc ( PacketIO_UDP * );
static PyObject * PacketIO_UDP_Type_str     ( PacketIO_UDP * );

static PyObject * PacketIO_UDP_pack   ( PacketIO_UDP *, PyObject * );
static PyObject * PacketIO_UDP_unpack ( PacketIO_UDP *, PyObject * );

static PyMethodDef PacketIO_UDP_methods[] = {
    { "pack",   (PyCFunction)PacketIO_UDP_pack,   METH_NOARGS },
    { "unpack", (PyCFunction)PacketIO_UDP_unpack, METH_O,     },
    { NULL }
};

static PyObject * PacketIO_UDP_getter ( PacketIO_UDP * self, void * param );
static int        PacketIO_UDP_setter ( PacketIO_UDP * self, PyObject * value, void * param );

#define PacketIO_UDP_SRC 0
#define PacketIO_UDP_DST 1
#define PacketIO_UDP_LEN 2
#define PacketIO_UDP_CRC 3

static PyGetSetDef PacketIO_UDP_getset[] = {
    { "src", (getter)PacketIO_UDP_getter, (setter)PacketIO_UDP_setter, "", (void*)PacketIO_UDP_SRC },
    { "dst", (getter)PacketIO_UDP_getter, (setter)PacketIO_UDP_setter, "", (void*)PacketIO_UDP_DST },
    { "len", (getter)PacketIO_UDP_getter, (setter)PacketIO_UDP_setter, "", (void*)PacketIO_UDP_LEN },
    { "crc", (getter)PacketIO_UDP_getter, (setter)PacketIO_UDP_setter, "", (void*)PacketIO_UDP_CRC },
    { NULL }
};

static PyMemberDef PacketIO_UDP_members[] = {
    { "data", T_OBJECT_EX, offsetof(PacketIO_UDP, data), READONLY, "data"},
    { NULL }
};

PyTypeObject PacketIO_UDP_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "packetio.udp",
    sizeof(PacketIO_UDP),
    0,    // itemsize
    (destructor)PacketIO_UDP_Type_dealloc,
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
    (reprfunc)PacketIO_UDP_Type_str,
    NULL, // getattro
    NULL, // setattro
    NULL, // as_buffer
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    "PacketIO.UDP class",
    NULL, // traverse
    NULL, // clear
    NULL, // richcompare
    0,    // weaklistoffset
    NULL, // iter
    NULL, // iternext
    PacketIO_UDP_methods,
    PacketIO_UDP_members,
    PacketIO_UDP_getset,
    NULL, // base
    NULL, // dict
    NULL, // descr_get
    NULL, // descr_set
    0,    // dictoffset
    (initproc)PacketIO_UDP_Type_init,
    NULL, // alloc
    PyType_GenericNew
};

static int PacketIO_UDP_Type_init(PacketIO_UDP *self, PyObject *args, PyObject *kwds) {
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
        memcpy(&self->udp, packet + offset, UDP_HDR_LEN);
    }

    return 0;
}

static void PacketIO_UDP_Type_dealloc(PacketIO_UDP *self) {
    if(NULL != self->data) {
        //free(self->data);
        self->data = NULL;
    }
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject * PacketIO_UDP_Type_str(PacketIO_UDP *self) {
    return PyUnicode_FromFormat(
        "%d/%d (%d)",
        htons(self->udp.src),
        htons(self->udp.dst),
        htons(self->udp.len)
        );
}

static PyObject * PacketIO_UDP_getter(PacketIO_UDP *self, void *param) {
    int field = (int)param;

    switch(field) {
        case PacketIO_UDP_SRC:
            return PyLong_FromLong(self->udp.src);
        case PacketIO_UDP_DST:
            return PyLong_FromLong(self->udp.dst);
        case PacketIO_UDP_LEN:
            return PyLong_FromLong(self->udp.len);
        case PacketIO_UDP_CRC:
            return PyLong_FromLong(self->udp.crc);
    }
    return NULL;
}

static int PacketIO_UDP_setter(PacketIO_UDP *self, PyObject *value, void *param) {
    int field = (int)param;

    switch(field) {
        case PacketIO_UDP_SRC:
            self->udp.src = PyLong_AsLong(value);
            break;
        case PacketIO_UDP_DST:
            self->udp.dst = PyLong_AsLong(value);
            break;
        case PacketIO_UDP_LEN:
            self->udp.len = PyLong_AsLong(value);
            break;
        case PacketIO_UDP_CRC:
            self->udp.crc = PyLong_AsLong(value);
            break;
    }

    return 0;
}

static PyObject * PacketIO_UDP_pack(PacketIO_UDP *self, PyObject *args) {

    Py_RETURN_NONE;
}

static PyObject * PacketIO_UDP_unpack(PacketIO_UDP *self, PyObject *args) {

    Py_RETURN_NONE;
}
