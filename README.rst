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

Fields left unset are computed when packing; anything set explicitly is
sent as-is, so malformed packets are easy to build on purpose.

Layers: Ethernet, VLAN (802.1Q), ARP, LLDP, IP, IPv6, ICMP, ICMPv6 (echo,
neighbor discovery), TCP, UDP, DHCP and DNS (including mDNS).

Devices
-------

``pcap.findalldevs()`` maps each capture device to what's known about it:

.. code-block:: python

    >>> pcap.findalldevs()['eth0']
    {'mac': b'\x02\x11"3DU', 'ipv4': ['10.0.0.5'], 'ip': '10.0.0.5', 'netmask': '255.255.255.0',
     'broadcast': '10.0.0.255', 'ipv6': ['fe80::11:22ff:fe33:4455']}

``ipv4`` and ``ipv6`` list every address, and ``ip``, ``netmask`` and
``broadcast`` are the first IPv4 address's. ``pcap.mac('eth0')`` returns just
the MAC; on macOS, only root sees the real one. ``pckt.vendor(mac)`` looks up
the vendor in Wireshark's list of OUIs.

Tools
-----

``pckt.stack.ghost`` pretends to be a host on the local network: it leases an
address with DHCP, or takes one with ``--ip``, and answers ARP and ping::

    sudo python3 -m pckt.stack.ghost                  # list devices
    sudo python3 -m pckt.stack.ghost eth0 --ip 10.0.0.66

``pckt.mapping.passive`` maps the hosts on the local network without sending
anything, from traffic that stays on the local link:

- IPv4 addresses from ARP and DHCP requests, IPv6 addresses from neighbor
  discovery
- names from DHCP, mDNS and LLDP
- the OS from DHCP: the vendor class, or else which options the client asks
  for (Windows, macOS, iOS, Android, Linux)
- descriptions, capabilities and management addresses from LLDP
- the vendor, from the MAC

It prints a line whenever a host's details change::

    sudo python3 -m pckt.mapping.passive eth0
    python3 -m pckt.mapping.passive --file capture.pcap

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
