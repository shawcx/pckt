#include "packetio.h"

static int        PacketIO_ICMP_Type_init    ( PacketIO_ICMP *, PyObject *, PyObject * );
static void       PacketIO_ICMP_Type_dealloc ( PacketIO_ICMP * );
static PyObject * PacketIO_ICMP_Type_str     ( PacketIO_ICMP * );

static PyObject * PacketIO_ICMP_pack   ( PacketIO_ICMP *, PyObject * );
static PyObject * PacketIO_ICMP_unpack ( PacketIO_ICMP *, PyObject * );

static PyMethodDef PacketIO_ICMP_methods[] = {
    { "pack",   (PyCFunction)PacketIO_ICMP_pack,   METH_NOARGS },
    { "unpack", (PyCFunction)PacketIO_ICMP_unpack, METH_O,     },
    { NULL }
};

static PyObject * PacketIO_ICMP_getter ( PacketIO_ICMP * self, void * param );
static int        PacketIO_ICMP_setter ( PacketIO_ICMP * self, PyObject * value, void * param );

#define PacketIO_ICMP_TYPE 0
#define PacketIO_ICMP_CODE 1
#define PacketIO_ICMP_CRC  2
#define PacketIO_ICMP_ID   3
#define PacketIO_ICMP_SEQ  4

static PyGetSetDef PacketIO_ICMP_getset[] = {
    { "type", (getter)PacketIO_ICMP_getter, (setter)PacketIO_ICMP_setter, "", (void*)PacketIO_ICMP_TYPE },
    { "code", (getter)PacketIO_ICMP_getter, (setter)PacketIO_ICMP_setter, "", (void*)PacketIO_ICMP_CODE },
    { "crc",  (getter)PacketIO_ICMP_getter, (setter)PacketIO_ICMP_setter, "", (void*)PacketIO_ICMP_CRC  },
    { "id",   (getter)PacketIO_ICMP_getter, (setter)PacketIO_ICMP_setter, "", (void*)PacketIO_ICMP_ID   },
    { "seq",  (getter)PacketIO_ICMP_getter, (setter)PacketIO_ICMP_setter, "", (void*)PacketIO_ICMP_SEQ  },
    { NULL }
};

static PyMemberDef PacketIO_ICMP_members[] = {
    { "data", T_OBJECT_EX, offsetof(PacketIO_ICMP, data), READONLY, "data"},
    { NULL }
};

PyTypeObject PacketIO_ICMP_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "packetio.icmp",
    sizeof(PacketIO_ICMP),
    0,    // itemsize
    (destructor)PacketIO_ICMP_Type_dealloc,
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
    (reprfunc)PacketIO_ICMP_Type_str,
    NULL, // getattro
    NULL, // setattro
    NULL, // as_buffer
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    "PacketIO.ICMP class",
    NULL, // traverse
    NULL, // clear
    NULL, // richcompare
    0,    // weaklistoffset
    NULL, // iter
    NULL, // iternext
    PacketIO_ICMP_methods,
    NULL, // members
    PacketIO_ICMP_getset,
    NULL, // base
    NULL, // dict
    NULL, // descr_get
    NULL, // descr_set
    0,    // dictoffset
    (initproc)PacketIO_ICMP_Type_init,
    NULL, // alloc
    PyType_GenericNew
};

static int PacketIO_ICMP_Type_init(PacketIO_ICMP *self, PyObject *args, PyObject *kwds) {
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
        memcpy(&self->icmp, packet + offset, ICMP_HDR_LEN);
    }

    return 0;
}

static void PacketIO_ICMP_Type_dealloc(PacketIO_ICMP *self) {
    if(NULL != self->data) {
        //free(self->data);
        self->data = NULL;
    }
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject * PacketIO_ICMP_Type_str(PacketIO_ICMP *self) {
    return PyUnicode_FromFormat(
        "ICMP %d/%d",
        self->icmp.type,
        self->icmp.code
        );
}

static PyObject * PacketIO_ICMP_getter(PacketIO_ICMP *self, void *param) {
    int field = (int)param;

    switch(field) {
        case PacketIO_ICMP_TYPE:
            return PyLong_FromLong(self->icmp.type);
        case PacketIO_ICMP_CODE:
            return PyLong_FromLong(self->icmp.code);
        case PacketIO_ICMP_CRC:
            return PyLong_FromLong(ntohs(self->icmp.crc));
        case PacketIO_ICMP_ID:
            return PyLong_FromLong(ntohs(self->icmp.id));
        case PacketIO_ICMP_SEQ:
            return PyLong_FromLong(ntohs(self->icmp.seq));
    }
    return NULL;
}

static int PacketIO_ICMP_setter(PacketIO_ICMP *self, PyObject *value, void *param) {
    int field = (int)param;

    switch(field) {
        case PacketIO_ICMP_TYPE:
            self->icmp.type = PyLong_AsLong(value);
            break;
        case PacketIO_ICMP_CODE:
            self->icmp.code = PyLong_AsLong(value);
            break;
        case PacketIO_ICMP_CRC:
            self->icmp.crc = htons(PyLong_AsLong(value));
            break;
        case PacketIO_ICMP_ID:
            self->icmp.id = htons(PyLong_AsLong(value));
            break;
        case PacketIO_ICMP_SEQ:
            self->icmp.seq = htons(PyLong_AsLong(value));
            break;
    }

    return 0;
}

static PyObject * PacketIO_ICMP_pack(PacketIO_ICMP *self, PyObject *args) {

    Py_RETURN_NONE;
}

static PyObject * PacketIO_ICMP_unpack(PacketIO_ICMP *self, PyObject *args) {

    Py_RETURN_NONE;
}
