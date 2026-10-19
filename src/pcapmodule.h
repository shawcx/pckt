#ifndef __PYPCAP_H__
#define __PYPCAP_H__

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <structmember.h>

#include <pcap/pcap.h>

#include <errno.h>
#include <limits.h>
#include <math.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef WIN32
 #include <io.h>
 #include <ws2tcpip.h>
#else
 #include <sys/socket.h>
 #include <sys/time.h>
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

#define DEFAULT_SNAPLEN 65535

// PCAP Module

PyMODINIT_FUNC PyInit_pcap(void);

static PyObject * PyPCAP_lib_version  ( PyObject * self );
static PyObject * PyPCAP_findalldevs  ( PyObject * self );
static PyObject * PyPCAP_mac          ( PyObject * self, PyObject * args );
static PyObject * PyPCAP_lookupnet    ( PyObject * self, PyObject * args );
static PyObject * PyPCAP_open_live    ( PyObject * self, PyObject * args );
static PyObject * PyPCAP_create       ( PyObject * self, PyObject * args );
static PyObject * PyPCAP_open_offline ( PyObject * self, PyObject * args, PyObject * kwds );
static PyObject * PyPCAP_open_dead    ( PyObject * self, PyObject * args, PyObject * kwds );
static PyObject * PyPCAP_compile_dead ( PyObject * self, PyObject * args, PyObject * kwds );
static PyObject * PyPCAP_datalink_name_to_val        ( PyObject * self, PyObject * args );
static PyObject * PyPCAP_datalink_val_to_name        ( PyObject * self, PyObject * args );
static PyObject * PyPCAP_datalink_val_to_description ( PyObject * self, PyObject * args );
static PyObject * PyPCAP_tstamp_type_name_to_val     ( PyObject * self, PyObject * args );
static PyObject * PyPCAP_tstamp_type_val_to_name     ( PyObject * self, PyObject * args );
#ifdef WIN32
static PyObject * PyPCAP_open_remote       ( PyObject * self, PyObject * args, PyObject * kwds );
static PyObject * PyPCAP_find_remote       ( PyObject * self, PyObject * args, PyObject * kwds );
static PyObject * PyPCAP_createsrcstr      ( PyObject * self, PyObject * args, PyObject * kwds );
static PyObject * PyPCAP_parsesrcstr       ( PyObject * self, PyObject * args );
static PyObject * PyPCAP_remoteact_accept  ( PyObject * self, PyObject * args, PyObject * kwds );
static PyObject * PyPCAP_remoteact_list    ( PyObject * self );
static PyObject * PyPCAP_remoteact_close   ( PyObject * self, PyObject * args );
static PyObject * PyPCAP_remoteact_cleanup ( PyObject * self );
#endif // WIN32

// findalldevs()'s description, flags and addresses of a device
static PyObject * describe_device ( pcap_if_t * device );

#ifdef WIN32
// helper functions for nice device names on windows
#define NPF_PREFIX "\\Device\\NPF_"
static PyObject * device_to_canonical ( const char * guid );
static int        canonical_to_device ( const char * name, char * device );

// a duplicate of a descriptor's Windows handle, for wpcap.dll to read or write
static int dup_handle ( int fd, intptr_t * copy );
#endif // WIN32

// Python Exception
static PyObject *PyPCAP_Error;

static PyMethodDef PyPCAP_module_methods[] = {
	{ "lib_version",  (PyCFunction)PyPCAP_lib_version,  METH_NOARGS,
	  "lib_version() => return pcap library version" },

	{ "findalldevs",  (PyCFunction)PyPCAP_findalldevs,  METH_NOARGS,
	  "findalldevs() => {device: {'description', 'flags', 'addresses', 'mac', 'ipv4', 'ipv6', 'ip', 'netmask', 'broadcast'}}, "
	  "the last six only when known" },

	{ "mac",          (PyCFunction)PyPCAP_mac,          METH_O,
	  "mac(device) => the interface's 6-byte hardware address" },

	{ "lookupnet",    (PyCFunction)PyPCAP_lookupnet,    METH_O,
	  "lookupnet(device) => (network, netmask) of the device's IPv4 address" },

	{ "open_live",    (PyCFunction)PyPCAP_open_live,    METH_VARARGS,
	  "open_live(device, [snaplen=65535], [promisc=True], [timeout_ms=0]) => handle" },

	{ "create",       (PyCFunction)PyPCAP_create,       METH_O,
	  "create(device) => handle to configure with the set_*() methods, then activate()" },

	{ "open_offline", (PyCFunction)PyPCAP_open_offline, METH_VARARGS | METH_KEYWORDS,
	  "open_offline(file, precision=TSTAMP_PRECISION_MICRO) => handle reading a capture "
	  "from a path, a file object or a descriptor (such as a pipe)" },

	{ "open_dead",    (PyCFunction)PyPCAP_open_dead,    METH_VARARGS | METH_KEYWORDS,
	  "open_dead(linktype=1, snaplen=65535, precision=TSTAMP_PRECISION_MICRO) => handle with no device, "
	  "for compiling filters and writing capture files" },

	{ "compile",      (PyCFunction)PyPCAP_compile_dead, METH_VARARGS | METH_KEYWORDS,
	  "compile(expression, linktype=1, snaplen=65535, optimize=True, netmask=None) => BPFProgram, without a handle" },

	{ "datalink_name_to_val",        (PyCFunction)PyPCAP_datalink_name_to_val,        METH_O,
	  "datalink_name_to_val(name) => link type number for a name such as 'EN10MB'" },
	{ "datalink_val_to_name",        (PyCFunction)PyPCAP_datalink_val_to_name,        METH_O,
	  "datalink_val_to_name(dlt) => name of a link type, or None" },
	{ "datalink_val_to_description", (PyCFunction)PyPCAP_datalink_val_to_description, METH_O,
	  "datalink_val_to_description(dlt) => description of a link type, or None" },
	{ "tstamp_type_name_to_val",     (PyCFunction)PyPCAP_tstamp_type_name_to_val,     METH_O,
	  "tstamp_type_name_to_val(name) => TSTAMP_* value for a name such as 'adapter'" },
	{ "tstamp_type_val_to_name",     (PyCFunction)PyPCAP_tstamp_type_val_to_name,     METH_O,
	  "tstamp_type_val_to_name(type) => name of a TSTAMP_* value, or None" },

#ifdef WIN32
	{ "open_remote",  (PyCFunction)PyPCAP_open_remote,  METH_VARARGS | METH_KEYWORDS,
	  "open_remote(source, snaplen=65535, flags=0, timeout_ms=100, username=None, password=None) => handle "
	  "for an rpcap://, file:// or local source" },
	{ "find_remote",  (PyCFunction)PyPCAP_find_remote,  METH_VARARGS | METH_KEYWORDS,
	  "find_remote(source, username=None, password=None) => findalldevs() for the devices behind a source" },
	{ "createsrcstr", (PyCFunction)PyPCAP_createsrcstr, METH_VARARGS | METH_KEYWORDS,
	  "createsrcstr(type, host=None, port=None, name=None) => source string from SRC_* and its parts" },
	{ "parsesrcstr",  (PyCFunction)PyPCAP_parsesrcstr,  METH_O,
	  "parsesrcstr(source) => (type, host, port, name)" },
	{ "remoteact_accept",  (PyCFunction)PyPCAP_remoteact_accept,  METH_VARARGS | METH_KEYWORDS,
	  "remoteact_accept(address=None, port=None, hostlist=None, username=None, password=None, ssl=False) => host "
	  "of an rpcapd in active mode, once it connects" },
	{ "remoteact_list",    (PyCFunction)PyPCAP_remoteact_list,    METH_NOARGS,
	  "remoteact_list() => hosts connected through remoteact_accept()" },
	{ "remoteact_close",   (PyCFunction)PyPCAP_remoteact_close,   METH_O,
	  "remoteact_close(host) closes the active-mode connection from a host" },
	{ "remoteact_cleanup", (PyCFunction)PyPCAP_remoteact_cleanup, METH_NOARGS,
	  "remoteact_cleanup() stops a remoteact_accept() waiting in another thread" },
#endif // WIN32

	{ NULL }
};

// PCAP Object

typedef struct
{
	PyObject_HEAD
	pcap_t *pd;
	int busy;      // set while loop(), dispatch() or next() runs with the GIL released
	int live;      // from open_live() or create(), not a file or open_dead()
#ifdef WIN32
	char device[MAX_PATH];
#else
	char device[IFNAMSIZ];
#endif
} PyPCAP;

#define PCAPCTX if(NULL == self->pd) { PyErr_SetString(PyPCAP_Error, "invalid handle"); return NULL; }

void       PyPCAP_Type_dealloc ( PyPCAP * self );
int        PyPCAP_Type_init    ( PyPCAP * self, PyObject * args, PyObject * kwds );
PyObject * PyPCAP_Type_iter    ( PyPCAP * self );

static PyObject * PyPCAP_activate             ( PyPCAP * self );
static PyObject * PyPCAP_set_snaplen          ( PyPCAP * self, PyObject * args );
static PyObject * PyPCAP_set_promisc          ( PyPCAP * self, PyObject * args );
static PyObject * PyPCAP_set_timeout          ( PyPCAP * self, PyObject * args );
static PyObject * PyPCAP_set_immediate_mode   ( PyPCAP * self, PyObject * args );
static PyObject * PyPCAP_set_buffer_size      ( PyPCAP * self, PyObject * args );
static PyObject * PyPCAP_set_rfmon            ( PyPCAP * self, PyObject * args );
static PyObject * PyPCAP_can_set_rfmon        ( PyPCAP * self );
static PyObject * PyPCAP_set_tstamp_type      ( PyPCAP * self, PyObject * args );
static PyObject * PyPCAP_list_tstamp_types    ( PyPCAP * self );
static PyObject * PyPCAP_set_tstamp_precision ( PyPCAP * self, PyObject * args );
static PyObject * PyPCAP_get_tstamp_precision ( PyPCAP * self );
#ifdef __linux__
static PyObject * PyPCAP_set_protocol_linux   ( PyPCAP * self, PyObject * args );
#endif
static PyObject * PyPCAP_geterr         ( PyPCAP * self );
static PyObject * PyPCAP_list_datalinks ( PyPCAP * self );
static PyObject * PyPCAP_datalink       ( PyPCAP * self );
static PyObject * PyPCAP_set_datalink   ( PyPCAP * self, PyObject * args );
static PyObject * PyPCAP_major_version  ( PyPCAP * self );
static PyObject * PyPCAP_minor_version  ( PyPCAP * self );
static PyObject * PyPCAP_is_swapped     ( PyPCAP * self );
static PyObject * PyPCAP_setdirection   ( PyPCAP * self, PyObject * args );
static PyObject * PyPCAP_setnonblock    ( PyPCAP * self, PyObject * args );
static PyObject * PyPCAP_getnonblock    ( PyPCAP * self );
static PyObject * PyPCAP_setfilter      ( PyPCAP * self, PyObject * args, PyObject * kwds );
static PyObject * PyPCAP_compile        ( PyPCAP * self, PyObject * args, PyObject * kwds );
static PyObject * PyPCAP_loop           ( PyPCAP * self, PyObject * args );
static PyObject * PyPCAP_dispatch       ( PyPCAP * self, PyObject * args );
static PyObject * PyPCAP_breakloop      ( PyPCAP * self );
static PyObject * PyPCAP_next_ex        ( PyPCAP * self );
#ifndef WIN32
static PyObject * PyPCAP_fileno         ( PyPCAP * self );
static PyObject * PyPCAP_get_required_select_timeout ( PyPCAP * self );
#endif
static PyObject * PyPCAP_inject         ( PyPCAP * self, PyObject * args );
static PyObject * PyPCAP_sendpacket     ( PyPCAP * self, PyObject * args );
static PyObject * PyPCAP_dump_open      ( PyPCAP * self, PyObject * args, PyObject * kwds );
static PyObject * PyPCAP_snapshot       ( PyPCAP * self );
static PyObject * PyPCAP_bufsize        ( PyPCAP * self );
static PyObject * PyPCAP_close          ( PyPCAP * self );
static PyObject * PyPCAP_stats          ( PyPCAP * self );
static PyObject * PyPCAP_enter          ( PyPCAP * self );
static PyObject * PyPCAP_exit           ( PyPCAP * self, PyObject * args );
#ifdef WIN32
static PyObject * PyPCAP_getevent       ( PyPCAP * self );
static PyObject * PyPCAP_setbuff        ( PyPCAP * self, PyObject * args );
static PyObject * PyPCAP_setmintocopy   ( PyPCAP * self, PyObject * args );
static PyObject * PyPCAP_setuserbuffer  ( PyPCAP * self, PyObject * args );
static PyObject * PyPCAP_setmode        ( PyPCAP * self, PyObject * args );
static PyObject * PyPCAP_stats_ex       ( PyPCAP * self );
static PyObject * PyPCAP_oid_get_request    ( PyPCAP * self, PyObject * args );
static PyObject * PyPCAP_oid_set_request    ( PyPCAP * self, PyObject * args );
static PyObject * PyPCAP_sendqueue_transmit ( PyPCAP * self, PyObject * args, PyObject * kwds );
static PyObject * PyPCAP_setsampling        ( PyPCAP * self, PyObject * args );
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
	{ "set_buffer_size",    (PyCFunction)PyPCAP_set_buffer_size,    METH_O,
	  "set_buffer_size(bytes), before activate()" },
	{ "set_rfmon",          (PyCFunction)PyPCAP_set_rfmon,          METH_O,
	  "set_rfmon(bool), before activate(): Wi-Fi monitor mode" },
	{ "can_set_rfmon",      (PyCFunction)PyPCAP_can_set_rfmon,      METH_NOARGS,
	  "can_set_rfmon() => whether monitor mode is available; False for files" },
	{ "set_tstamp_type",    (PyCFunction)PyPCAP_set_tstamp_type,    METH_O,
	  "set_tstamp_type(TSTAMP_*), before activate(); an unsupported type returns a warning string" },
	{ "list_tstamp_types",  (PyCFunction)PyPCAP_list_tstamp_types,  METH_NOARGS,
	  "list_tstamp_types() => [(type, name, description), ...]" },
	{ "set_tstamp_precision", (PyCFunction)PyPCAP_set_tstamp_precision, METH_O,
	  "set_tstamp_precision(TSTAMP_PRECISION_MICRO or _NANO), before activate()" },
	{ "get_tstamp_precision", (PyCFunction)PyPCAP_get_tstamp_precision, METH_NOARGS,
	  "get_tstamp_precision() => TSTAMP_PRECISION_MICRO or _NANO" },
#ifdef __linux__
	{ "set_protocol_linux", (PyCFunction)PyPCAP_set_protocol_linux, METH_O,
	  "set_protocol_linux(ethertype), before activate(): capture only that protocol, such as 0x0806" },
#endif
	{ "geterr",         (PyCFunction)PyPCAP_geterr,         METH_NOARGS,
	  "geterr() => libpcap's last error message for this handle" },
	{ "list_datalinks", (PyCFunction)PyPCAP_list_datalinks, METH_NOARGS,
	  "list_datalinks() => [(dlt, name, description), ...]" },
	{ "datalink",       (PyCFunction)PyPCAP_datalink,       METH_NOARGS,
	  "datalink() => (dlt, name, description)" },
	{ "set_datalink",   (PyCFunction)PyPCAP_set_datalink,   METH_O,
	  "set_datalink(dlt) switches to another of list_datalinks()" },
	{ "major_version",  (PyCFunction)PyPCAP_major_version,  METH_NOARGS,
	  "major_version() => major version of a capture file's format" },
	{ "minor_version",  (PyCFunction)PyPCAP_minor_version,  METH_NOARGS,
	  "minor_version() => minor version of a capture file's format" },
	{ "is_swapped",     (PyCFunction)PyPCAP_is_swapped,     METH_NOARGS,
	  "is_swapped() => whether a capture file is in the other byte order" },
	{ "setdirection",   (PyCFunction)PyPCAP_setdirection,   METH_VARARGS,
	  "setdirection(D_IN | D_OUT | D_INOUT)" },
	{ "setnonblock",    (PyCFunction)PyPCAP_setnonblock,    METH_O,
	  "setnonblock(bool)" },
	{ "getnonblock",    (PyCFunction)PyPCAP_getnonblock,    METH_NOARGS,
	  "getnonblock() => bool" },
	{ "setfilter",      (PyCFunction)PyPCAP_setfilter,      METH_VARARGS | METH_KEYWORDS,
	  "setfilter(filter, optimize=True, netmask=None) applies a BPF expression or a BPFProgram. "
	  "The netmask, for 'ip broadcast', defaults to the device's" },
	{ "compile",        (PyCFunction)PyPCAP_compile,        METH_VARARGS | METH_KEYWORDS,
	  "compile(expression, optimize=True, netmask=None) => BPFProgram for this handle's link type" },
	{ "loop",           (PyCFunction)PyPCAP_loop,           METH_VARARGS,
	  "loop(callback, [count=-1], *extra) calls callback(data, ts, wirelen, *extra) per packet; "
	  "stops after count packets, on breakloop(), at the end of a file, on Ctrl-C or when the callback raises. "
	  "loop(dumper) writes the packets to a Dumper" },
	{ "dispatch",       (PyCFunction)PyPCAP_dispatch,       METH_VARARGS,
	  "dispatch(callback, [count=-1], *extra) => how many packets: like loop(), for one buffer of packets" },
	{ "breakloop",      (PyCFunction)PyPCAP_breakloop,      METH_NOARGS,
	  "breakloop() stops loop() or dispatch(), including from another thread" },
	{ "next",           (PyCFunction)PyPCAP_next_ex,        METH_NOARGS,
	  "next() => (data, ts, wirelen), or None when no packet is available yet (timeout or non-blocking); "
	  "raises EOFError at the end of a file or after breakloop()" },
#ifndef WIN32
	{ "fileno",         (PyCFunction)PyPCAP_fileno,         METH_NOARGS,
	  "fileno() => descriptor to select() on; use with setnonblock(True). "
	  "On Linux the read timeout is not honored while the interface is idle." },
	{ "get_required_select_timeout", (PyCFunction)PyPCAP_get_required_select_timeout, METH_NOARGS,
	  "get_required_select_timeout() => seconds after which a select() on fileno() must time out, or None" },
#endif
	{ "inject",         (PyCFunction)PyPCAP_inject,         METH_O,
	  "inject(bytes) => bytes sent" },
	{ "sendpacket",     (PyCFunction)PyPCAP_sendpacket,     METH_O,
	  "sendpacket(bytes)" },
	{ "dump_open",      (PyCFunction)PyPCAP_dump_open,      METH_VARARGS | METH_KEYWORDS,
	  "dump_open(file, append=False) => Dumper writing a capture file with this handle's link type and snaplen "
	  "to a path, a file object or a descriptor" },
	{ "snapshot",       (PyCFunction)PyPCAP_snapshot,       METH_NOARGS,
	  "snapshot() => snaplen" },
	{ "bufsize",        (PyCFunction)PyPCAP_bufsize,        METH_NOARGS,
	  "bufsize() => size of the capture buffer in bytes" },
	{ "close",          (PyCFunction)PyPCAP_close,          METH_NOARGS,
	  "close()" },
	{ "stats",          (PyCFunction)PyPCAP_stats,          METH_NOARGS,
	  "stats() => (received, dropped, dropped by interface)" },
	{ "__enter__",      (PyCFunction)PyPCAP_enter,          METH_NOARGS,  NULL },
	{ "__exit__",       (PyCFunction)PyPCAP_exit,           METH_VARARGS, NULL },
#ifdef WIN32
	{ "getevent",       (PyCFunction)PyPCAP_getevent,       METH_NOARGS,
	  "getevent() => the event handle that is signaled when packets arrive" },
	{ "setbuff",        (PyCFunction)PyPCAP_setbuff,        METH_O,
	  "setbuff(bytes) sets the driver's buffer size" },
	{ "setmintocopy",   (PyCFunction)PyPCAP_setmintocopy,   METH_O,
	  "setmintocopy(bytes) the driver waits for before a read returns" },
	{ "setuserbuffer",  (PyCFunction)PyPCAP_setuserbuffer,  METH_O,
	  "setuserbuffer(bytes) sets the size of the buffer packets are read into" },
	{ "setmode",        (PyCFunction)PyPCAP_setmode,        METH_O,
	  "setmode(MODE_CAPT or MODE_STAT)" },
	{ "stats_ex",       (PyCFunction)PyPCAP_stats_ex,       METH_NOARGS,
	  "stats_ex() => {'recv', 'drop', 'ifdrop', 'capt', 'sent', 'netdrop'}" },
	{ "oid_get_request",    (PyCFunction)PyPCAP_oid_get_request,    METH_VARARGS,
	  "oid_get_request(oid, size) => bytes: queries an adapter OID" },
	{ "oid_set_request",    (PyCFunction)PyPCAP_oid_set_request,    METH_VARARGS,
	  "oid_set_request(oid, data) sets an adapter OID" },
	{ "sendqueue_transmit", (PyCFunction)PyPCAP_sendqueue_transmit, METH_VARARGS | METH_KEYWORDS,
	  "sendqueue_transmit(queue, sync=False) => bytes sent: sends a SendQueue, keeping its timing with sync=True" },
	{ "setsampling",    (PyCFunction)PyPCAP_setsampling,    METH_VARARGS,
	  "setsampling(method, value): SAMP_* sampling for remote captures" },
#endif // WIN32
	{ NULL }
};

static PyTypeObject PyPCAP_Type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name      = "pckt.pcap.Handle",
	.tp_doc       = "pcap capture handle, from open_live(), create(), open_offline() or open_dead(); "
	                "iterating over it yields (data, ts, wirelen)",
	.tp_basicsize = sizeof(PyPCAP),
	.tp_flags     = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
	.tp_new       = PyType_GenericNew,
	.tp_init      = (initproc)PyPCAP_Type_init,
	.tp_dealloc   = (destructor)PyPCAP_Type_dealloc,
	.tp_iter      = (getiterfunc)PyPCAP_Type_iter,
	.tp_methods   = PyPCAP_Type_methods,
};

// Packets from iter(handle)

typedef struct
{
	PyObject_HEAD
	PyPCAP *handle;
} PyPacketIter;

void       PyPacketIter_Type_dealloc  ( PyPacketIter * self );
PyObject * PyPacketIter_Type_iternext ( PyPacketIter * self );

static PyTypeObject PyPacketIter_Type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name      = "pckt.pcap.PacketIterator",
	.tp_doc       = "(data, ts, wirelen) for each packet, from iter(handle)",
	.tp_basicsize = sizeof(PyPacketIter),
	.tp_flags     = Py_TPFLAGS_DEFAULT,
	.tp_dealloc   = (destructor)PyPacketIter_Type_dealloc,
	.tp_iter      = PyObject_SelfIter,
	.tp_iternext  = (iternextfunc)PyPacketIter_Type_iternext,
};

// Compiled BPF filters

typedef struct
{
	PyObject_HEAD
	struct bpf_program program;
	int compiled;  // from pcap_compile(), so pcap_freecode() frees it; otherwise PyMem_Free()
} PyBPF;

PyObject * PyBPF_Type_new     ( PyTypeObject * type, PyObject * args, PyObject * kwds );
void       PyBPF_Type_dealloc ( PyBPF * self );
Py_ssize_t PyBPF_Type_len     ( PyBPF * self );
PyObject * PyBPF_Type_item    ( PyBPF * self, Py_ssize_t index );

static PyObject * PyBPF_match        ( PyBPF * self, PyObject * args );
static PyObject * PyBPF_instructions ( PyBPF * self );

static PyMethodDef PyBPF_Type_methods[] = {
	{ "match",        (PyCFunction)PyBPF_match,        METH_O,
	  "match(packet) => True if the filter accepts the packet" },
	{ "instructions", (PyCFunction)PyBPF_instructions, METH_NOARGS,
	  "instructions() => the program as text, one line per instruction, as tcpdump -d prints it" },
	{ NULL }
};

static PySequenceMethods PyBPF_Type_sequence = {
	.sq_length = (lenfunc)PyBPF_Type_len,
	.sq_item   = (ssizeargfunc)PyBPF_Type_item,
};

static PyTypeObject PyBPF_Type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name        = "pckt.pcap.BPFProgram",
	.tp_doc         = "BPFProgram(instructions): a BPF filter from compile(), or from (code, jt, jf, k) tuples "
	                  "as tcpdump -ddd prints them; it is a sequence of those tuples",
	.tp_basicsize   = sizeof(PyBPF),
	.tp_flags       = Py_TPFLAGS_DEFAULT,
	.tp_new         = PyBPF_Type_new,
	.tp_dealloc     = (destructor)PyBPF_Type_dealloc,
	.tp_as_sequence = &PyBPF_Type_sequence,
	.tp_iter        = PySeqIter_New,
	.tp_methods     = PyBPF_Type_methods,
};

// Capture file writers

typedef struct
{
	PyObject_HEAD
	pcap_dumper_t *dumper;
	int snaplen;   // packets longer than this are truncated, as a capture would
	int nano;      // the file stores nanoseconds rather than microseconds
	int busy;      // set while loop() writes to it with the GIL released
} PyDumper;

void PyDumper_Type_dealloc ( PyDumper * self );

static PyObject * PyDumper_write ( PyDumper * self, PyObject * args, PyObject * kwds );
static PyObject * PyDumper_flush ( PyDumper * self );
static PyObject * PyDumper_tell  ( PyDumper * self );
static PyObject * PyDumper_close ( PyDumper * self );
static PyObject * PyDumper_enter ( PyDumper * self );
static PyObject * PyDumper_exit  ( PyDumper * self, PyObject * args );

static PyMethodDef PyDumper_Type_methods[] = {
	{ "write",     (PyCFunction)PyDumper_write, METH_VARARGS | METH_KEYWORDS,
	  "write(data, ts=None, wirelen=None): ts defaults to now, and wirelen to len(data)" },
	{ "flush",     (PyCFunction)PyDumper_flush, METH_NOARGS,
	  "flush() writes buffered packets to the file" },
	{ "tell",      (PyCFunction)PyDumper_tell,  METH_NOARGS,
	  "tell() => bytes written so far, including the file header" },
	{ "close",     (PyCFunction)PyDumper_close, METH_NOARGS,
	  "close() flushes and closes the file" },
	{ "__enter__", (PyCFunction)PyDumper_enter, METH_NOARGS,  NULL },
	{ "__exit__",  (PyCFunction)PyDumper_exit,  METH_VARARGS, NULL },
	{ NULL }
};

static PyTypeObject PyDumper_Type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name      = "pckt.pcap.Dumper",
	.tp_doc       = "capture file writer, from handle.dump_open()",
	.tp_basicsize = sizeof(PyDumper),
	.tp_flags     = Py_TPFLAGS_DEFAULT,
	.tp_dealloc   = (destructor)PyDumper_Type_dealloc,
	.tp_methods   = PyDumper_Type_methods,
};

#ifdef WIN32

// Npcap send queues

typedef struct
{
	PyObject_HEAD
	pcap_send_queue *queue;
} PySendQueue;

PyObject * PySendQueue_Type_new     ( PyTypeObject * type, PyObject * args, PyObject * kwds );
void       PySendQueue_Type_dealloc ( PySendQueue * self );

static PyObject * PySendQueue_queue ( PySendQueue * self, PyObject * args, PyObject * kwds );
static PyObject * PySendQueue_size  ( PySendQueue * self, void * closure );
static PyObject * PySendQueue_used  ( PySendQueue * self, void * closure );

static PyMethodDef PySendQueue_Type_methods[] = {
	{ "queue", (PyCFunction)PySendQueue_queue, METH_VARARGS | METH_KEYWORDS,
	  "queue(data, ts=None, wirelen=None) adds a packet; ts sets its timing for sync transmits" },
	{ NULL }
};

static PyGetSetDef PySendQueue_Type_getset[] = {
	{ "size", (getter)PySendQueue_size, NULL, "capacity in bytes", NULL },
	{ "used", (getter)PySendQueue_used, NULL, "bytes queued, including packet headers", NULL },
	{ NULL }
};

static PyTypeObject PySendQueue_Type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name      = "pckt.pcap.SendQueue",
	.tp_doc       = "SendQueue(memsize): up to memsize bytes of packets for handle.sendqueue_transmit()",
	.tp_basicsize = sizeof(PySendQueue),
	.tp_flags     = Py_TPFLAGS_DEFAULT,
	.tp_new       = PySendQueue_Type_new,
	.tp_dealloc   = (destructor)PySendQueue_Type_dealloc,
	.tp_methods   = PySendQueue_Type_methods,
	.tp_getset    = PySendQueue_Type_getset,
};

#endif // WIN32

#endif // __PYPCAP_H__
