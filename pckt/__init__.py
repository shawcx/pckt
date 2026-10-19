import functools
import logging
import os

from .layer import Layer, checksum, mac

from .ethernet import Ethernet
from .vlan     import VLAN

from .llc  import LLC, SNAP
from .arp  import ARP
from .cdp  import CDP
from .lldp import LLDP
from .ip   import IP
from .ipv6 import IPv6

from .icmp   import ICMP, ICMP_EchoRequest, ICMP_EchoReply
from .icmpv6 import ICMPv6, ICMPv6_EchoRequest, ICMPv6_EchoReply, ICMPv6_NeighborSolicit, ICMPv6_NeighborAdvert
from .tcp  import TCP
from .udp  import UDP

from .layer7 import DHCP, DHCP_Request, DHCPv6, DHCPv6Relay, DNS, DNSQuestion, DNSRR, NBNS, SSDP

# library code logs; leave output to the application
logging.getLogger(__name__).addHandler(logging.NullHandler())

@functools.lru_cache(maxsize=None)
def _manuf():
    '''
    Wireshark's manuf file: "<prefix>[/bits]<TAB>short name<TAB>full name" per
    line, with the prefix a 24-, 28- or 36-bit IEEE block. Returns
    {bits: {prefix as an int: (short, full)}}, loaded on first use.
    '''
    blocks = {36: {}, 28: {}, 24: {}}
    with open(os.path.join(os.path.dirname(__file__), 'manuf'), 'r', encoding='utf-8') as f:
        for line in f:
            if line.startswith('#'):
                continue
            fields = [field.strip() for field in line.split('\t')]
            if len(fields) < 2 or not fields[1]:
                continue
            (prefix, _, bits) = fields[0].partition('/')
            try:
                prefix = bytes.fromhex(prefix.replace(':', ''))
                bits = int(bits) if bits else 8 * len(prefix)
            except ValueError:
                continue
            if bits in blocks:
                full = fields[2] if len(fields) > 2 and fields[2] else fields[1]
                blocks[bits][int.from_bytes(prefix, 'big') >> (8 * len(prefix) - bits)] = (fields[1], full)
    return blocks

def vendor(addr, full=False):
    '''
    vendor for a MAC address (bytes or 'aa:bb:..' string), or None: Wireshark's
    short name ('VMware'), or the registered name ('VMware, Inc.') with full=True
    '''
    value = int.from_bytes(mac(addr)[:6], 'big')
    for (bits, block) in _manuf().items():
        names = block.get(value >> (48 - bits))
        if names:
            return names[full]
    return None
