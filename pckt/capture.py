
import select


def packets(pd, interval=0.5):
    '''
    Yield (data, ts, wirelen) for each packet from an open pcap handle, and
    None whenever interval seconds pass without one, so the caller can do
    periodic work. Stops at the end of a file.

    Iterating over the handle isn't enough for that on its own: on Linux the
    capture timeout isn't honored while the interface is idle, so a read can
    block until traffic arrives (though Ctrl-C still interrupts it).
    '''
    from .pcap import error

    selectable = hasattr(pd, 'fileno')
    if selectable:
        try:
            pd.setnonblock(True)
        except error:
            # savefiles: reads never wait on an idle interface
            selectable = False

    while True:
        try:
            result = pd.next()
        except EOFError:
            return

        if result is not None:
            yield result
        elif not selectable:
            # windows: next() returned on the capture timeout
            yield None
        elif not select.select([pd], [], [], interval)[0]:
            yield None
