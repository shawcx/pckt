'''
Checked by `mypy --strict typing_check.py` in CI, never run: the types the
stub pckt/pcap.pyi gives common calls. unittest doesn't collect it.
'''

from typing import assert_type

from pckt import pcap


def check(pd: pcap.Handle, dumper: pcap.Dumper) -> None:
    assert_type(pcap.open_offline('capture.pcap'), pcap.Handle)
    assert_type(pd.next(), tuple[bytes, float, int] | None)
    for data, ts, wirelen in pd:
        assert_type(ts, float)
    pd.loop(dumper)
    pd.loop(dumper.write)
    pd.loop(lambda data, ts, wirelen, extra: None, -1, 'extra')
    assert_type(pd.dispatch(lambda data, ts, wirelen: None), int)
    assert_type(pcap.findalldevs()['lo']['addresses'][0]['netmask'], str | None)
    assert_type(pcap.findalldevs()['lo']['ipv4'], list[str])
    assert_type(pd.compile('udp', netmask='255.255.255.0').match(b''), bool)
    assert_type(len(pd.compile('udp')), int)
    program = pcap.BPFProgram(list(pcap.compile('udp', linktype=1)))
    assert_type(program[0], tuple[int, int, int, int])
    for code, jt, jf, k in program:
        assert_type(k, int)
    assert_type(pd.bufsize(), int)
    with pd.dump_open('copy.pcap') as out:
        assert_type(out, pcap.Dumper)
    with pcap.open_dead(precision=pcap.TSTAMP_PRECISION_NANO) as dead:
        assert_type(dead.set_tstamp_type(pcap.TSTAMP_HOST), str | None)
