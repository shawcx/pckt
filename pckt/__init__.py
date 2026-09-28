import os

from .layer import Layer, checksum

from .Ethernet import Ethernet
from .VLAN     import VLAN

from .ARP  import ARP
from .IP   import IP
from .IPv6 import IPv6

from .ICMP import *
from .ICMPv6 import *
from .TCP  import TCP
from .UDP  import UDP

from .layer7 import DHCP, DHCP_Request

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
