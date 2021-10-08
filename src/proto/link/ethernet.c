#include "packetio.h"

static int        PacketIO_Ethernet_Type_init    ( PacketIO_Ethernet *, PyObject *, PyObject * );
static void       PacketIO_Ethernet_Type_dealloc ( PacketIO_Ethernet * );
static PyObject * PacketIO_Ethernet_Type_str     ( PacketIO_Ethernet * );

static PyObject * PacketIO_Ethernet_pack   ( PacketIO_Ethernet *, PyObject * );
static PyObject * PacketIO_Ethernet_unpack ( PacketIO_Ethernet *, PyObject * );

static PyMethodDef PacketIO_Ethernet_methods[] = {
    { "pack",   (PyCFunction)PacketIO_Ethernet_pack,   METH_NOARGS },
    { "unpack", (PyCFunction)PacketIO_Ethernet_unpack, METH_O,     },
    { NULL }
};

static PyObject * PacketIO_Ethernet_getter ( PacketIO_Ethernet * self, void * param );
static int        PacketIO_Ethernet_setter ( PacketIO_Ethernet * self, PyObject * value, void * param );

#define PacketIO_Ethernet_DST  0
#define PacketIO_Ethernet_SRC  1
#define PacketIO_Ethernet_TYPE 2

static PyGetSetDef PacketIO_Ethernet_getset[] = {
    { "dst",  (getter)PacketIO_Ethernet_getter, (setter)PacketIO_Ethernet_setter, "", (void*)PacketIO_Ethernet_DST  },
    { "src",  (getter)PacketIO_Ethernet_getter, (setter)PacketIO_Ethernet_setter, "", (void*)PacketIO_Ethernet_SRC  },
    { "type", (getter)PacketIO_Ethernet_getter, (setter)PacketIO_Ethernet_setter, "", (void*)PacketIO_Ethernet_TYPE },
    { NULL }
};

static PyMemberDef PacketIO_Ethernet_members[] = {
    { "layer3", T_OBJECT_EX, offsetof(PacketIO_Ethernet, layer3), READONLY, "layer3"},
    { "ip",     T_OBJECT_EX, offsetof(PacketIO_Ethernet, layer3), READONLY, "IP alias"},
    { NULL }
};

PyTypeObject PacketIO_Ethernet_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "packetio.ethernet",
    sizeof(PacketIO_Ethernet),
    0,    // itemsize
    (destructor)PacketIO_Ethernet_Type_dealloc,
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
    (reprfunc)PacketIO_Ethernet_Type_str,
    NULL, // getattro
    NULL, // setattro
    NULL, // as_buffer
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    "PacketIO.Ethernet class",
    NULL, // traverse
    NULL, // clear
    NULL, // richcompare
    0,    // weaklistoffset
    NULL, // iter
    NULL, // iternext
    PacketIO_Ethernet_methods,
    PacketIO_Ethernet_members,
    PacketIO_Ethernet_getset,
    NULL, // base
    NULL, // dict
    NULL, // descr_get
    NULL, // descr_set
    0,    // dictoffset
    (initproc)PacketIO_Ethernet_Type_init,
    NULL, // alloc
    PyType_GenericNew
};

static int PacketIO_Ethernet_Type_init(PacketIO_Ethernet *self, PyObject *args, PyObject *kwds) {
    PyObject *bytes = NULL;
    int offset = 0;
    int ok;

    ok = PyArg_ParseTuple(args, "|Oi", &bytes, &offset);
    if(!ok) {
        PyErr_SetString(PyExc_TypeError, "invalid arguments");
        return -1;
    }

    self->layer3 = NULL;

    if(bytes) {
        if(!PyBytes_Check(bytes)) {
            PyErr_SetString(PyExc_TypeError, "expected bytes");
            return -1;
        }

        char *packet = PyBytes_AsString(bytes);
        memcpy(&self->ethernet, packet, ETHERNET_HDR_LEN);

        switch(ntohs(self->ethernet.type)) {
            case ETHERNET_IP:
                self->layer3 = PyObject_CallFunctionObjArgs(
                    (PyObject *)&PacketIO_IP_Type,
                    bytes,
                    PyLong_FromLong(ETHERNET_HDR_LEN),
                    NULL
                    );
                break;
            case ETHERNET_ARP:
                self->layer3 = PyObject_CallFunctionObjArgs(
                    (PyObject *)&PacketIO_ARP_Type,
                    bytes,
                    PyLong_FromLong(ETHERNET_HDR_LEN),
                    NULL
                    );
                break;
            case ETHERNET_RARP:
                break;
        }
    }

    return 0;
}

static void PacketIO_Ethernet_Type_dealloc(PacketIO_Ethernet *self) {
    if(NULL != self->layer3) {
        Py_TYPE(self->layer3)->tp_free(self->layer3);
        self->layer3 = NULL;
    }
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject * PacketIO_Ethernet_Type_str(PacketIO_Ethernet *self) {
    return PyUnicode_FromFormat(
        "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x/%.2x:%.2x:%.2x:%.2x:%.2x:%.2x %.4x %S",
        self->ethernet.src[0],
        self->ethernet.src[1],
        self->ethernet.src[2],
        self->ethernet.src[3],
        self->ethernet.src[4],
        self->ethernet.src[5],
        self->ethernet.dst[0],
        self->ethernet.dst[1],
        self->ethernet.dst[2],
        self->ethernet.dst[3],
        self->ethernet.dst[4],
        self->ethernet.dst[5],
        ntohs(self->ethernet.type),
        self->layer3
        );
}

static PyObject * PacketIO_Ethernet_getter(PacketIO_Ethernet *self, void *param) {
    int field = (int)param;
    switch(field) {
        case PacketIO_Ethernet_DST:
            return PyBytes_FromStringAndSize((char *)self->ethernet.dst, ETHERNET_ADDR_LEN);
        case PacketIO_Ethernet_SRC:
            return PyBytes_FromStringAndSize((char *)self->ethernet.src, ETHERNET_ADDR_LEN);
        case PacketIO_Ethernet_TYPE:
            return PyLong_FromLong(ntohs(self->ethernet.type));
    }
    return NULL;
}

static int PacketIO_Ethernet_setter(PacketIO_Ethernet *self, PyObject *value, void *param) {
    int field = (int)param;

    switch(field) {
        case PacketIO_Ethernet_DST:
            {
                if(PyBytes_Check(value)) {
                    memcpy(self->ethernet.dst, PyBytes_AsString(value), ETHERNET_ADDR_LEN);
                }
                else if(PyUnicode_Check(value)) {
                    sscanf(PyUnicode_AsUTF8(value), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                        &self->ethernet.dst[0],
                        &self->ethernet.dst[1],
                        &self->ethernet.dst[2],
                        &self->ethernet.dst[3],
                        &self->ethernet.dst[4],
                        &self->ethernet.dst[5]
                        );
                }
                else {
                    return -1;
                }
            }
            break;
        case PacketIO_Ethernet_SRC:
            {
                if(PyBytes_Check(value)) {
                    memcpy(self->ethernet.src, PyBytes_AsString(value), ETHERNET_ADDR_LEN);
                }
                else if(PyUnicode_Check(value)) {
                    sscanf(PyUnicode_AsUTF8(value), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                        &self->ethernet.src[0],
                        &self->ethernet.src[1],
                        &self->ethernet.src[2],
                        &self->ethernet.src[3],
                        &self->ethernet.src[4],
                        &self->ethernet.src[5]
                        );
                }
                else {
                    return -1;
                }
            }
            break;
        case PacketIO_Ethernet_TYPE:
            self->ethernet.type = htons(PyLong_AsLong(value));
            break;
    }

    return 0;
}

static PyObject * PacketIO_Ethernet_pack(PacketIO_Ethernet *self, PyObject *args) {
    Py_RETURN_NONE;
}

static PyObject * PacketIO_Ethernet_unpack(PacketIO_Ethernet *self, PyObject *args) {
    Py_RETURN_NONE;
}
