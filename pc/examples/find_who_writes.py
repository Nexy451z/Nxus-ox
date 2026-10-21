"""'Find out what writes this address' - the workflow Nxus exists for.

    python pc/examples/find_who_writes.py

On hardware this replaces the Cheat Engine workflow that cannot work on a
console (CE sees JIT code, not the ARM32 instruction).  Here it runs against the
mock Switch; the protocol and the analysis are identical.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from nxus import protocol as P                                     # noqa: E402
from nxus.client import NxusClient                                 # noqa: E402
from nxus.mock_switch import MockSwitch, MAIN_BASE, MONEY_ADDRESS  # noqa: E402


def main():
    server = MockSwitch().start()
    client = NxusClient('127.0.0.1', server.port, timeout=10.0).connect()
    try:
        md = client.get_metadata()
        print(f"target : {md['title']:016X}  main={md['main_base']:#010X}")

        print("\n[1] switch to debug mode (dmnt lets go of the process)")
        st = client.debug_attach()
        print(f"    attached={st['attached']} watch_style={st['watch_style']}")

        print(f"\n[2] watch for writes to {MONEY_ADDRESS:#010X}")
        breaks = client.break_set(MONEY_ADDRESS, kind=P.BREAK_KIND['NxusBp_Write'], size=4, slot=0x10)
        for b in breaks:
            print(f"    slot {b['slot']:#x}: kind={b['kind']} size={b['size']} addr={b['address']:#x}")

        print("\n[3] the game writes the value (in the real thing: buy something)")
        pc_in_module = 0x12345
        server.simulate_watch_hit(MONEY_ADDRESS, MAIN_BASE + pc_in_module, value=3940)

        print("\n[4] the console reports the hit")
        hit = None
        import time
        deadline = time.time() + 3.0
        while time.time() < deadline and hit is None:
            ev = client.poll_event(timeout=0.1)
            if ev and ev['type'] == P.EVT['BreakHit']:
                v = P.BREAK_HIT.unpack(ev['payload'])
                hit = dict(address=v[4], pc=v[5], lr=v[6], r=list(v[9:22]), kind=v[1])
        if hit is None:
            print("    no hit received")
            return 1

        print(f"    trapped write to {hit['address']:#010X}")
        print(f"    pc = {hit['pc']:#010X}   -> main + {hit['pc'] - MAIN_BASE:#x}")
        print(f"    r3 = {hit['r'][3]}  (the value being written)")
        print(f"    -> open Ghidra at main+{hit['pc'] - MAIN_BASE:#x} to see the storing instruction")

        print("\n[5] cleanup: clear the watchpoint, leave debug mode")
        client.hit_clear()
        client.break_clear(0x10)
        client.debug_detach()
        print(f"    attached={client.debug_status()['attached']}")
        return 0
    finally:
        client.close()
        server.stop()


if __name__ == '__main__':
    raise SystemExit(main())
