# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`pckt` is a Python 3 library for building packets a layer at a time, chaining the layers into a full frame, decoding frames back into layers, and sending or capturing them through its own libpcap binding (`pckt.pcap`). The distribution name on PyPI would be `pckt` (unclaimed as of 2026-09).

## Layout

- **`pckt/layer.py`**: the `Layer` base class that every protocol subclasses (`ethernet.py`, `vlan.py`, `arp.py`, `ip.py`, `ipv6.py`, `icmp.py`, `icmpv6.py`, `tcp.py`, `udp.py`, `layer7/dhcp.py`, `layer7/dns.py`).
  - Fields are declared in a `FIELDS` tuple of `(name, default)` pairs in wire order, and set with keyword constructors (`IP(dst='10.0.0.2')`). A layer's payload is another `Layer`, `bytes`, any object with `pack()`, or `None`.
  - `a / b` returns a **copy** of the chain with `b` appended as the innermost payload. `pkt[UDP]` finds a layer, and `UDP in pkt` tests for one.
  - A field left at its `None` default is computed when packing: lengths, header lengths (options get padded), checksums, and the next layer's ethertype, IP protocol or UDP ports. Those come from the payload class's `ETHERTYPE`/`IP_PROTO` attributes or its `udp_ports()` method. An explicitly set value is always packed as-is.
  - Each subclass implements `build(data, outer)`, which returns its header plus `data`, and `unpack(pkt)`, which returns the rest. TCP, UDP and ICMPv6 checksums call `outer.pseudo_header()` (implemented by `IP` and `IPv6`), so they're 0 when there's no enclosing IP layer.
  - `Cls.decode(bytes)` builds the whole chain. It finds the next class through `Layer.lookup()`, a registry of subclasses keyed by `ETHERTYPE`/`IP_PROTO`/`UDP_PORTS` (a tuple of values is allowed), and through the `subclass_for()` hook (e.g. ICMP echo types). Decoded fields are concrete values, so re-packing reproduces the input exactly; set a field to `None` to recompute it after editing. DNS is the exception to plain re-encoding: senders differ in which names they compress, so a decoded `DNS` keeps its original bytes and packs them until any field changes (see `_wire`).
  - MACs and payloads are `bytes` (MAC fields also accept `'aa:bb:..'` strings), and IP addresses are `str`. TCP's sequence number field is named `syn`. `DHCP.options` is a list of `(code, bytes)` tuples, or raw bytes packed as-is. `DNS` has `questions`/`answers`/`authority`/`additional` lists of `DNSQuestion`/`DNSRR` dataclasses. Their `data` is typed for A/AAAA/NS/CNAME/PTR/MX/SOA/SRV/TXT and raw bytes otherwise (including EDNS `OPT`). There's no DNS-over-TCP length prefix. IPv6 extension headers are not decoded.
- **`src/pcapmodule.c`/`.h`**: the C extension `pckt.pcap`:
  - Module functions are `findalldevs()`, `mac()`, `open_live()`, `create()`, `open_offline()` and `lib_version()`.
  - A `create()` handle takes `set_snaplen()`/`set_promisc()`/`set_timeout()`/`set_immediate_mode()` and then `activate()`, which returns `None` or a warning string. Until then `snapshot()`/`datalink()` raise, and the setters raise once it's active.
  - pypcap3 (github.com/shawcx/pypcap3) was merged into this binding; its history is in the repo, reached through the "Merge pypcap3's history" commit.
  - `loop()` calls `callback(data, ts, wirelen, *extra)` with the GIL released. `next()` returns `(data, ts, wirelen)`, `None` when nothing is available yet, and raises `EOFError` at the end of a file. `sendpacket()`/`inject()` send the bytes unchanged.
  - `win32.c` is a fragment that's `#include`d at the bottom of `pcapmodule.c`. On Windows, `open_live()`/`create()` also accept a connection name ("Ethernet") and `findalldevs()` reports it as `name`. The Windows and macOS (`__APPLE__` in `find_mac()`) paths are untested.
- **`pckt/capture.py`**: `packets(pd, interval)` yields packets plus a `None` every idle interval, using `select()` on `fileno()`. Use it rather than a blocking `next()` loop: on Linux, libpcap ignores the capture timeout while the interface is idle, so `next()`/`loop()` can block until traffic arrives, and Ctrl-C is only noticed then.
- **`pckt/stack/ghost.py`** (`python3 -m pckt.stack.ghost <dev> [--ip ...]`): a fake host that leases an address with DHCP (with retries) or uses `--ip`, and answers ARP and ping. `Ghost` takes an open handle so tests can drive it with a fake.
- **`pckt/mapping/passive.py`**: maps MAC → IP, hostname, OS and vendor from ARP and DHCP requests, live or with `--file`. `PassiveMapper.process(frame)` is pure logic.
- **`pckt.vendor(mac)`** looks up the bundled `pckt/manuf` (UTF-8 Wireshark OUI list). Library code logs through `logging` (the package logger has a `NullHandler`), and only `main()` functions configure output.
- **`scripts/`**: standalone tools that aren't packaged (`sniff.py`, NetBIOS `namescan*.py`).

## Build / test

- Build dependencies: libpcap headers (`libpcap-dev`) and Python dev headers. Metadata is in `pyproject.toml`, and `setup.py` only holds the platform-dependent extension settings.
- Build in place: `python3 setup.py build_ext --inplace` puts `pckt/pcap*.so` next to the sources. Install with `pip install .`.
- Tests (unittest, no dependencies): `PYTHONPATH=. python3 -m unittest discover -s test`. Run a single one with `PYTHONPATH=.:test python3 -m unittest test_layers.TestDecode.test_udp`.
  - `test_layers.py` needs no build. `test_pcap.py` and `test_stack.py` use pcap files and a fake handle, and skip without the extension.
  - `test_live.py` re-runs itself inside `unshare -rn` (an unprivileged user and network namespace, no root). It creates a veth pair, then runs `ghost` against the kernel's own ARP/ping and against dnsmasq, runs the passive mapper, captures through a `create()` handle, and checks that `DNS` queries get answered by dnsmasq and that its responses re-pack exactly. It's skipped when namespaces, `ip`, `ping` or `dnsmasq` are unavailable, and adds about 6 seconds.
- Independent check for new layers: write frames to a pcap file, then run `tcpdump -nn -vv -r file.pcap` (it reports `[udp sum ok]`, `cksum ... (correct)` and `[icmp6 sum ok]`) or tshark (with `-o udp.check_checksum:TRUE` and the like). Reading files doesn't need root.
- Anything else that needs a real interface can be run the same way: `unshare -rn sh -c 'ip link add v0 type veth peer name v1; ...'`. In there, background jobs started by `sh` ignore SIGINT, so start Python children from Python if you need Ctrl-C behaviour.
