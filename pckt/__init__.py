import os

#from .Ethernet import Ethernet
#from .ARP  import ARP
#from .IP   import IP
#from .ICMP import *
#from .TCP  import TCP
#from .UDP  import UDP
#from DHCP import DHCP_Request

def _parse():
    manuf = {}
    for entry in open(os.path.join(os.path.dirname(__file__), 'manuf'), 'r'):
        try:
            (prefix,owner) = entry.rstrip().split(' ', 1)
        except:
            continue
        manuf[prefix] = owner
    return manuf

manuf = _parse()
