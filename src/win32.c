
/*
#ifdef WIN32
static PyObject * PyPCAP_stats_ex(PyPCAP *self) {
    struct pcap_stat ps;

    PCAPCTX;

    if(-1 == pcap_stats_ex(self->pd, &ps)) {
        PyErr_SetString(PyPCAP_Error, pcap_geterr(self->pd));
        return NULL;
    }

    return Py_BuildValue("IIII", ps.ps_recv, ps.ps_drop, ps.ps_ifdrop, ps.bs_capt);
}
#endif
*/

#ifdef WIN32
static PyObject * PyPCAP_getevent(PyPCAP *self) {
    PCAPCTX;

    return Py_BuildValue("i", pcap_getevent(self->pd));
}
#endif

#ifdef WIN32

/*
 * Code that allows you to open a device by the name (e.g. Local Area Connection) instead of a GUID on Windows
 */

#define CANONICALPATH "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}"

// the connection name for the {GUID} part of an NPF device name, or NULL
static PyObject * device_to_canonical(const char *guid) {
    PyObject *name = NULL;
    HKEY hkey;
    char path[MAX_PATH];
    char value[MAX_PATH];
    DWORD len;

    snprintf(path, sizeof(path), CANONICALPATH "\\%s\\Connection", guid);

    if(ERROR_SUCCESS != RegOpenKeyEx(HKEY_LOCAL_MACHINE, path, 0, KEY_QUERY_VALUE, &hkey)) {
        return NULL;
    }

    len = sizeof(value);

    if(ERROR_SUCCESS == RegQueryValueEx(hkey, "Name", NULL, NULL, (LPBYTE)value, &len)) {
        name = PyUnicode_FromString(value);
    }

    RegCloseKey(hkey);

    return name;
}

// fills device (MAX_PATH) with the NPF device name for a connection name; -1 if there's none
static int canonical_to_device(const char *name, char *device) {
    HKEY base;
    HKEY connection;
    LONG hr;
    char path[MAX_PATH];
    char canon[MAX_PATH];
    char guid[MAX_PATH];
    int idx;
    DWORD len;

    if(ERROR_SUCCESS != RegOpenKeyEx(HKEY_LOCAL_MACHINE, CANONICALPATH, 0, KEY_ENUMERATE_SUB_KEYS, &base)) {
        return -1;
    }

    for(idx = 0; ; ++idx) {
        len = sizeof(guid);

        hr = RegEnumKeyEx(base, idx, guid, &len, NULL, NULL, NULL, NULL);
        if(ERROR_SUCCESS != hr && ERROR_MORE_DATA != hr) {
            break;
        }
        if(38 != len || '{' != guid[0]) {
            continue;
        }

        snprintf(path, sizeof(path), "%s\\Connection", guid);

        if(ERROR_SUCCESS != RegOpenKeyEx(base, path, 0, KEY_QUERY_VALUE, &connection)) {
            continue;
        }

        len = sizeof(canon);

        hr = RegQueryValueEx(connection, "Name", NULL, NULL, (LPBYTE)canon, &len);
        RegCloseKey(connection);
        if(ERROR_SUCCESS != hr) {
            continue;
        }

        if(!_stricmp(canon, name)) {
            snprintf(device, MAX_PATH, NPF_PREFIX "%s", guid);
            RegCloseKey(base);
            return 0;
        }
    }

    RegCloseKey(base);
    return -1;
}

#endif // WIN32
