
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

PyObject * device_to_canonical(char *guid) {
    PyObject *name = NULL;
    HKEY hkey;
    char value[MAX_PATH];
    DWORD len;

    sprintf(value, CANONICALPATH "\\%s\\Connection", guid);

    if(ERROR_SUCCESS != RegOpenKeyEx(HKEY_LOCAL_MACHINE, value, 0, KEY_QUERY_VALUE, &hkey)) {
        return NULL;
    }

    len = MAX_PATH;

    if(ERROR_SUCCESS == RegQueryValueEx(hkey, "Name", NULL, NULL, value, &len)) {
        name = PyString_FromString(value);
    }

    RegCloseKey(hkey);

    return name;
}

int canonical_to_device(char *name, char *device) {
    HKEY base;
    HKEY connection;
    HRESULT hr;
    char path[MAX_PATH];
    char cannon[MAX_PATH];
    char guid[MAX_PATH];
    int idx;
    DWORD len;

    if(ERROR_SUCCESS != RegOpenKeyEx(HKEY_LOCAL_MACHINE, CANONICALPATH, 0, KEY_ENUMERATE_SUB_KEYS, &base)) {
        return -1;
    }

    for(idx = 0; ; ++idx) {
        len = MAX_PATH;

        hr = RegEnumKeyEx(base, idx, guid, &len, NULL, NULL, NULL, NULL);
        if(ERROR_SUCCESS != hr && ERROR_MORE_DATA != hr) {
            break;
        }
        if(38 != len || '{' != guid[0]) {
            continue;
        }

        sprintf(path, "%s\\Connection", guid);

        hr = RegOpenKeyEx(base, path, 0, KEY_QUERY_VALUE, &hkey_connection);
        if(ERROR_SUCESS != hr) {
            break;
        }

        len = MAX_PATH;

        hr = RegQueryValueEx(connection, "Name", NULL, NULL, (LPBYTE)cannon, &len);
        if(ERROR_SUCESS != hr) {
            break;
        }

        RegCloseKey(connection);

        if(!stricmp(cannon, name)) {
            sprintf(device, "\\Device\\NPF_%s", guid);
            RegCloseKey(base);
            return 0;
        }
    }

    RegCloseKey(base);
    return -1;
}

#endif // WIN32
