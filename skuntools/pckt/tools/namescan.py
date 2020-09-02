#!/usr/bin/env python3

import sys
import socket
import threading
import random
import struct

message = b'\t\xf5\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00!\x00\x01'

sema = threading.BoundedSemaphore(32)

results = {}

def scanip(ip):
    sema.acquire()
    skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    skt.settimeout(2.0)
    try:
        skt.sendto(message, (ip, 137))
        (msg,client) = skt.recvfrom(1024)
        if struct.unpack('B', msg[56])[0]:
            results[client[0]] = msg[57:72].strip()
            sys.stdout.write('+')
            sys.stdout.flush()

    except socket.timeout:
        sys.stdout.write('.')
        sys.stdout.flush()
    except Exception as e:
        print(e)
    sema.release()

if len(sys.argv) == 1:
    print('e.g.', sys.argv[0], '172.30.1,2.1-255')
    sys.exit(-1)

def parse(o):
    res = []
    sets = o.split(',')
    for s in sets:
        ranges = list(int(r) for r in s.split('-'))
        if len(ranges) == 1:
            res.append(ranges[0])
        else:
            res.extend(range(ranges[0],ranges[1]+1))
    return res

(A,B,C,D) = (parse(o) for o in sys.argv[1].split('.'))
for a in A:
    for b in B:
        for c in C:
            for d in D:
                t = threading.Thread(target=scanip, args=('%d.%d.%d.%d' % (a,b,c,d),))
                t.start()

t.join()
print()

for ip,name in results.items():
    print(ip, '=>', name)

