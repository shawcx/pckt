import logging
import os

from .layer import Layer, checksum, mac

from .ethernet import Ethernet
from .vlan     import VLAN

from .arp  import ARP
from .ip   import IP
from .ipv6 import IPv6

from .icmp   import ICMP, ICMP_EchoRequest, ICMP_EchoReply
from .icmpv6 import ICMPv6, ICMPv6_EchoRequest, ICMPv6_EchoReply, ICMPv6_NeighborSolicit, ICMPv6_NeighborAdvert
from .tcp  import TCP
from .udp  import UDP

from .layer7 import DHCP, DHCP_Request, DNS, DNSQuestion, DNSRR

# library code logs; leave output to the application
logging.getLogger(__name__).addHandler(logging.NullHandler())

def _parse():
    manuf = {}
    with open(os.path.join(os.path.dirname(__file__), 'manuf'), 'r', encoding='utf-8') as f:
        for entry in f:
            try:
                (prefix,owner) = entry.rstrip().split(' ', 1)
            except ValueError:
                continue
            manuf[prefix] = owner
    return manuf

manuf = _parse()

def vendor(addr):
    '''vendor name for a MAC address (bytes or 'aa:bb:..' string), or None'''
    return manuf.get(':'.join('%.2X' % o for o in mac(addr)[:3]))
