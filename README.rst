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

Layers: Ethernet, VLAN (802.1Q), ARP, IP, IPv6, ICMP, ICMPv6 (echo,
neighbor discovery), TCP, UDP, DHCP and DNS.

Install
-------

Needs the libpcap headers (e.g. ``libpcap-dev``) and a C compiler::

    pip install .

Tests::

    python3 setup.py build_ext --inplace
    PYTHONPATH=. python3 -m unittest discover -s test
