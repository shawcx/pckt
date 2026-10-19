pckt
====

Build packets a layer at a time, chain the layers together, and send or
capture them with libpcap.

.. code-block:: python

    from pckt import Ethernet, IP, UDP, DHCP_Request
    from pckt import pcap

    pkt = Ethernet(src='00:11:22:33:44:55') / IP() / UDP() / DHCP_Request(clientmac='00:11:22:33:44:55')
    frame = pkt.pack()        # lengths, checksums, ethertype, protocol and ports filled in

    decoded = Ethernet.decode(frame)
    decoded[UDP].dst          # 67

    pd = pcap.open_live('eth0')
    pd.sendpacket(frame)
    pd.loop(lambda data, ts, wirelen: print(Ethernet.decode(data)))

    # or set options before the capture starts
    pd = pcap.create('eth0')
    pd.set_immediate_mode(True)
    pd.activate()
    for data, ts, wirelen in pd:    # until Ctrl-C
        print(ts, Ethernet.decode(data))

Fields left unset are computed when packing; anything set explicitly is
sent as-is, so malformed packets are easy to build on purpose.

Layers: Ethernet (including 802.3 with LLC and SNAP), VLAN (802.1Q), ARP,
LLDP, CDP, IP, IPv6, ICMP, ICMPv6 (echo, neighbor discovery), TCP, UDP, DHCP,
DHCPv6, DNS (including mDNS and LLMNR), NetBIOS name service and SSDP.

Devices
-------

``pcap.findalldevs()`` maps each capture device to what's known about it:

.. code-block:: python

    >>> pcap.findalldevs()['eth0']
    {'mac': b'\x02\x11"3DU', 'ipv4': ['10.0.0.5'], 'ip': '10.0.0.5', 'netmask': '255.255.255.0',
     'broadcast': '10.0.0.255', 'ipv6': ['fe80::11:22ff:fe33:4455']}

``ipv4`` and ``ipv6`` list every address, and ``ip``, ``netmask`` and
``broadcast`` are the first IPv4 address's. Each device also has its
``description``, ``flags`` (``pcap.IF_UP`` and so on) and ``addresses``, with
each address's netmask, broadcast and destination. ``pcap.mac('eth0')``
returns just the MAC; on macOS, only root sees the real one.
``pckt.vendor(mac)`` looks up the vendor in Wireshark's list of OUIs.

Capture files and filters
-------------------------

Capture DNS traffic to a file until Ctrl-C, then read it back:

.. code-block:: python

    pd = pcap.open_live('eth0')
    pd.setfilter('udp port 53')
    with pd.dump_open('dns.pcap') as dumper:
        try:
            pd.loop(dumper)       # written by libpcap, keeping capture timestamps
        except KeyboardInterrupt:
            pass

    with pcap.open_offline('dns.pcap') as pd:
        for data, ts, wirelen in pd:
            print(ts, Ethernet.decode(data)[UDP].dst)

``open_offline()`` also reads from a file object or a descriptor, such as
``tcpdump -w -`` through a pipe. ``open_dead()`` gives a handle without a
device, for writing frames you've built with ``dumper.write(frame, ts)``.

Filters compile to programs you can test frames against, without a device::

    program = pcap.compile('udp port 53')   # for Ethernet, unless linktype= says otherwise
    program.match(frame)                    # True
    list(program)                           # [(40, 0, 0, 12), ...], as tcpdump -ddd prints them

Install
-------

Needs Python 3.11 or later, the libpcap headers (e.g. ``libpcap-dev``) and a C
compiler::

    pip install .

Debian package (``python3-pckt``, built as ``../python3-pckt_*.deb``)::

    sudo apt build-dep .
    dpkg-buildpackage -us -uc -b

Tests::

    python3 setup.py build_ext --inplace
    PYTHONPATH=. python3 -m unittest discover -s test
