"""The whole MHXX workflow against the mock Switch - no console required.

    python pc/examples/mhxx_workflow.py

It reproduces exactly what Nxus will do on hardware:
  1. find the current money address with a scan
  2. refine after "buying something"
  3. find a static pointer chain to that address (session-independent)
  4. export an Atmosphère cheat code
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from nxus import protocol as P                                  # noqa: E402
from nxus.client import NxusClient                              # noqa: E402
from nxus.mock_switch import MockSwitch, MAIN_BASE, DATA_BASE, MONEY_ADDRESS  # noqa: E402

def main():
    server = MockSwitch().start()
    client = NxusClient('127.0.0.1', server.port, timeout=10.0).connect()
    try:
        md = client.get_metadata()
        print(f"target      : title {md['title']:016X}")
        print(f"main        : {md['main_base']:#010X} + {md['main_size']:#X}")

        start_money = server.target.money
        print(f"\n[1] money is {start_money} - scanning for it")
        client.scan_begin(start_money, value_size=4, cmp_mode=P.CMP['NxusCmp_Equal'],
                          scope=P.SCOPE['NxusScope_All'])
        st = client.scan_wait()
        hits = client.scan_all_hits()
        print(f"    hits: {st['hits']} -> {[hex(h['address']) for h in hits[:4]]}")

        print("\n[2] buy something (the game changes the value)")
        server.target.set_money(start_money - 2500)
        st = client.scan_next(cmp_mode=P.CMP['NxusCmp_Decreased'])
        hits = client.scan_all_hits()
        print(f"    after decrease: {st['hits']} hit(s) -> {[hex(h['address']) for h in hits]}")

        if not hits:
            print("    (nothing left - the workflow would stop here)")
            return 1
        money_address = hits[0]['address']
        print(f"    money address = {money_address:#010X}  (moves between sessions!)")

        print("\n[3] pointer scan: find a chain rooted in the module's static data")
        chains = client.ptr_scan_begin(money_address, module_base=md['main_base'],
                                       max_depth=3, max_offset=0x1000, value_width=4)
        for i, c in enumerate(chains[:5]):
            steps = "".join(f" +{s:#x}" for s in c['steps'])
            print(f"    chain {i}: main+{c['root_offset']:#x}{steps} +{c['final_offset']:#x}")

        if not chains:
            print("    no chain found")
            return 1

        print("\n[4] export an Atmosphere cheat code")
        text = client.cheat_export(0, 9999999, value_width=4, is_32bit=True)
        print("    " + text.replace("\n", "\n    ").rstrip())
        print("\n    -> paste into atmosphere/contents/<titleid>/cheats/<buildid>.txt")
        return 0
    finally:
        client.close()
        server.stop()


if __name__ == '__main__':
    raise SystemExit(main())
