"""End-to-end protocol tests: PC client <-> mock Switch.

These run the real client against a real TCP socket speaking the real wire
format, which is as close to hardware as we can get before the console arrives.
"""
import os
import struct
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PC = os.path.dirname(HERE)
sys.path.insert(0, PC)

from nxus import protocol as P                      # noqa: E402
from nxus.client import NxusClient, NxusError       # noqa: E402
from nxus.mock_switch import (MockSwitch, MONEY_ADDRESS, MAIN_BASE, DATA_BASE,  # noqa: E402
                               HEAP_BASE,
                              BUILD_ID)


class ReadSplit(unittest.TestCase):
    """The reference client must honour the console's advertised read cap: asking
    for more is rejected outright, so a big read has to be split."""

    @classmethod
    def setUpClass(cls):
        cls.server = MockSwitch().start()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def test_large_read_is_split(self):
        client = NxusClient('127.0.0.1', self.server.port, timeout=5.0).connect()
        try:
            status = client.get_status()
            self.assertEqual(client.max_read, status['max_read'])
            cap = client.max_read

            want = cap + 4096                 # must arrive as exactly two requests
            self.server.read_sizes.clear()
            data = client.read(HEAP_BASE, want)
            self.assertEqual(len(data), want)
            chunks = [s for s in self.server.read_sizes if s > 0]
            self.assertLessEqual(max(chunks), cap, 'asked for more than the advertised cap')
            self.assertEqual(len(chunks), 2, f'expected 2 reads, got {len(chunks)}')
            self.assertEqual(chunks, [cap, 4096])
        finally:
            client.close()


class MockE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = MockSwitch(watchdog_ms=100000).start()
        cls.client = NxusClient('127.0.0.1', cls.server.port, timeout=5.0).connect()

    @classmethod
    def tearDownClass(cls):
        cls.client.close()
        cls.server.stop()

    # ---- basics ----

    def test_01_status(self):
        st = self.client.get_status()
        self.assertEqual(st['proto'], P.PROTO_VERSION)
        self.assertFalse(st['paused'])
        self.assertEqual(st['title'], 0x0100C3800049C000)
        self.assertTrue(st['flags'] & P.ST['NXUS_ST_HAS_PROCESS'])

    def test_02_metadata(self):
        md = self.client.get_metadata()
        self.assertEqual(md['title'], 0x0100C3800049C000)
        self.assertEqual(md['main_base'], MAIN_BASE)
        self.assertTrue(md['build_id'].startswith(BUILD_ID[:8].hex()))

    def test_03_mappings(self):
        count = self.client.get_mapping_count()
        self.assertEqual(count, 4)
        maps = self.client.get_mappings(0, 8)
        self.assertEqual(len(maps), 4)
        self.assertIn(MAIN_BASE, [m['base'] for m in maps])
        main = next(m for m in maps if m['base'] == MAIN_BASE)
        self.assertTrue(main['perm'] & P.PERM['NXUS_PERM_X'])

    def test_04_query(self):
        info = self.client.query(MONEY_ADDRESS)
        self.assertLessEqual(info['base'], MONEY_ADDRESS)
        self.assertGreater(info['base'] + info['size'], MONEY_ADDRESS)
        self.assertTrue(info['perm'] & P.PERM['NXUS_PERM_W'])

    def test_05_read_write(self):
        address = MAIN_BASE + 0x100
        self.client.write(address, struct.pack('<I', 0xCAFEBABE))
        self.assertEqual(self.client.read(address, 4), struct.pack('<I', 0xCAFEBABE))

        # write through the protocol and observe the change in the target
        self.client.write(MONEY_ADDRESS, struct.pack('<i', 1234))
        self.assertEqual(self.server.target.money, 1234)
        self.assertEqual(int.from_bytes(self.client.read(MONEY_ADDRESS, 4), 'little'), 1234)

    # ---- the actual Nxus workflow ----

    def test_06_scan_first_finds_the_money(self):
        self.server.target.set_money(6440)
        self.client.scan_reset()
        st = self.client.scan_begin(6440, value_size=4, cmp_mode=P.CMP['NxusCmp_Equal'],
                                    scope=P.SCOPE['NxusScope_All'])
        self.assertEqual(st['scan_state'], P.SCAN_STATE['NxusScanState_Done'])
        self.assertEqual(st['hits'], 1)

        hits = self.client.scan_hits(0, 16)
        self.assertEqual(batch_total(hits), 1)
        self.assertEqual(hits['hits'][0]['address'], MONEY_ADDRESS)
        self.assertEqual(hits['hits'][0]['value'], 6440)

    def test_07_scan_refine_decreased(self):
        """Buy something: money goes down -> the refine pass must keep one hit."""
        self.server.target.set_money(3940)          # 6440 - 2500
        st = self.client.scan_next(cmp_mode=P.CMP['NxusCmp_Decreased'])
        self.assertEqual(st['hits'], 1)
        hits = self.client.scan_hits(0, 16)
        self.assertEqual(hits['hits'][0]['address'], MONEY_ADDRESS)
        self.assertEqual(hits['hits'][0]['value'], 3940)

    def test_08_scan_refine_increased(self):
        self.server.target.set_money(9999999)
        st = self.client.scan_next(cmp_mode=P.CMP['NxusCmp_Increased'])
        self.assertEqual(st['hits'], 1)
        hits = self.client.scan_hits(0, 16)
        self.assertEqual(hits['hits'][0]['value'], 9999999)

    def test_09_scan_refine_equal_target(self):
        st = self.client.scan_next(value=9999999, cmp_mode=P.CMP['NxusCmp_Equal'])
        self.assertEqual(st['hits'], 1)

    def test_10_scan_paging(self):
        total = self.client.scan_status()['hits']
        self.assertEqual(total, 1)
        page = self.client.scan_hits(0, 1)
        self.assertEqual(page['count'], 1)
        empty = self.client.scan_hits(1, 1)
        self.assertEqual(empty['count'], 0)
        self.assertEqual(empty['total'], 1)

    def test_11_scan_reset(self):
        self.client.scan_reset()
        st = self.client.scan_status()
        self.assertEqual(st['hits'], 0)
        self.assertEqual(st['scan_state'], P.SCAN_STATE['NxusScanState_Idle'])

    # ---- safety / plumbing ----

    def test_12_pause_and_watchdog_auto_resume(self):
        self.client.pause()
        self.assertTrue(self.client.get_status()['paused'])
        self.client.heartbeat()
        self.assertTrue(self.client.get_status()['paused'])

        # stop heartbeating with a short watchdog: the Switch must resume and
        # push an async AutoResume event
        self.client.set_config(watchdog_timeout_ms=300)
        self.server.watchdog_ms = 300
        deadline = time.time() + 3.0
        event = None
        while time.time() < deadline and event is None:
            event = self.client.poll_event(timeout=0.1)
        self.assertIsNotNone(event, "no AutoResume event received")
        self.assertEqual(event['type'], P.EVT['AutoResume'])
        self.assertFalse(self.client.get_status()['paused'])
        self.client.set_config(watchdog_timeout_ms=15000)

    def test_13_unknown_command_is_reported(self):
        with self.assertRaises(NxusError) as ctx:
            self.client.request(0x7FFE)
        self.assertEqual(ctx.exception.result, P.make_result(P.ERR_NOT_IMPLEMENTED))

    def test_14_scan_events_do_not_break_requests(self):
        """An async event must not corrupt the request/response correlation."""
        self.server.send_event(P.EVT['HotkeyPaused'], struct.pack('<I', 1))
        st = self.client.get_status()          # still works, seq correlation intact
        self.assertEqual(st['proto'], P.PROTO_VERSION)
        seen = None
        deadline = time.time() + 2.0
        while time.time() < deadline and seen is None:
            seen = self.client.poll_event(timeout=0.05)
        self.assertIsNotNone(seen)
        self.assertEqual(seen['type'], P.EVT['HotkeyPaused'])

    # ---- pointer scan / permanent cheat ----

    def test_16_pointer_scan_finds_the_static_chain(self):
        """The address moves between sessions; the static chain does not."""
        chains = self.client.ptr_scan_begin(MONEY_ADDRESS, module_base=MAIN_BASE,
                                            max_depth=3, max_offset=0x1000, value_width=4)
        self.assertGreaterEqual(len(chains), 1, "no pointer chain found")
        want_root = (DATA_BASE - MAIN_BASE) + 0x1000
        match = [c for c in chains if c['root_offset'] == want_root
                 and c['steps'] == [0x20] and c['final_offset'] == 4]
        self.assertEqual(len(match), 1,
                         f"expected the planted chain, got {chains}")

    def test_17_cheat_export_is_valid_atmosphere_code(self):
        chains = self.client.ptr_scan_get()
        want_root = (DATA_BASE - MAIN_BASE) + 0x1000
        index = next(i for i, c in enumerate(chains) if c['root_offset'] == want_root)
        text = self.client.cheat_export(index, 9999999, value_width=4, is_32bit=True)
        expected = ("[Nxus]\n"
                    f"540F0000 {want_root:08X}\n"
                    "540F1000 00000020\n"
                    "780F0000 00000004\n"
                    "640F0000 00000000 0098967F\n")
        self.assertEqual(text, expected)

    def test_18_cheat_export_uses_8byte_loads_for_64bit_titles(self):
        chains = self.client.ptr_scan_get()
        text = self.client.cheat_export(0, 9999999, value_width=4, is_32bit=False)
        self.assertTrue(text.splitlines()[1].startswith('580F0000'), text)

    def test_19_pointer_scan_depth_limit_is_honoured(self):
        # depth 1 can only see a static pointer that points straight at the value
        chains = self.client.ptr_scan_begin(MONEY_ADDRESS, module_base=MAIN_BASE,
                                            max_depth=1, max_offset=0x1000, value_width=4)
        self.assertEqual(chains, [], f"depth 1 should not resolve a 2-hop chain: {chains}")

    # ---- debug mode ----

    def test_20_debug_attach_detach(self):
        st = self.client.debug_attach()
        self.assertTrue(st['attached'])
        self.assertEqual(st['watch_style'], P.WATCH_STYLE_LINK5)
        st = self.client.debug_status()
        self.assertTrue(st['attached'])

    def test_21_set_write_watchpoint(self):
        breaks = self.client.break_set(MONEY_ADDRESS, kind=P.BREAK_KIND['NxusBp_Write'],
                                       size=4, slot=0x10)
        self.assertEqual(len(breaks), 1)
        self.assertEqual(breaks[0]['address'], MONEY_ADDRESS)
        self.assertEqual(breaks[0]['slot'], 0x10)
        st = self.client.debug_status()
        self.assertEqual(st['break_count'], 1)

    def test_22_watchpoint_hit_arrives_as_event(self):
        """The payoff: the console tells us which instruction wrote the money."""
        pc = MAIN_BASE + 0x12345
        self.server.simulate_watch_hit(MONEY_ADDRESS, pc, value=3940)

        event = None
        deadline = time.time() + 3.0
        while time.time() < deadline and event is None:
            event = self.client.poll_event(timeout=0.1)
        self.assertIsNotNone(event, "no BreakHit event received")
        self.assertEqual(event['type'], P.EVT['BreakHit'])

        v = P.BREAK_HIT.unpack(event['payload'])
        hit = dict(index=v[0], kind=v[1], slot=v[2], thread_id_low=v[3], address=v[4],
                   pc=v[5], lr=v[6], sp=v[7], cpsr=v[8], r=list(v[9:22]), tick=v[22])
        self.assertEqual(hit['address'], MONEY_ADDRESS)
        self.assertEqual(hit['pc'], pc)
        self.assertEqual(hit['kind'], P.BREAK_KIND['NxusBp_Write'])
        # what the user actually needs: which module and offset
        self.assertEqual(hit['pc'] - MAIN_BASE, 0x12345)
        self.assertEqual(hit['r'][3], 3940)      # r3 held the value being written

    def test_23_hit_get_pages_the_same_data(self):
        hits = self.client.hit_get(8)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]['pc'], MAIN_BASE + 0x12345)
        self.assertEqual(hits[0]['address'], MONEY_ADDRESS)

    def test_24_threads_and_registers(self):
        threads = self.client.thread_list()
        self.assertGreaterEqual(len(threads), 1)
        thread_id = threads[0]['thread_id']

        ctx = self.client.regs_get(thread_id)
        self.assertEqual(ctx['thread_id'], thread_id)
        self.assertEqual(ctx['pc'], 0x00712345)

        ctx['r'][0] = 0xCAFEBABE
        self.client.regs_set(ctx)
        again = self.client.regs_get(thread_id)
        self.assertEqual(again['r'][0], 0xCAFEBABE, "register write did not stick")

    def test_25_hit_and_break_cleanup(self):
        self.client.hit_clear()
        self.assertEqual(self.client.hit_get(8), [])

        self.client.break_clear(0x10)
        self.assertEqual(self.client.break_list(), [])
        self.assertEqual(self.client.debug_status()['break_count'], 0)

        self.client.debug_detach()
        self.assertFalse(self.client.debug_status()['attached'])

    def test_26_debug_watch_style_is_configurable(self):
        """The probe tells us which encoding this console accepts; the client can
        switch without a rebuild."""
        cfg = self.client.set_debug_config(style=P.WATCH_STYLE_PLAIN, auto_continue=0)
        self.assertIsNotNone(cfg)
        self.server.watch_style = P.WATCH_STYLE_PLAIN
        self.assertEqual(self.client.debug_status()['watch_style'], P.WATCH_STYLE_PLAIN)
        self.client.set_debug_config(style=P.WATCH_STYLE_LINK5, auto_continue=1)
        self.server.watch_style = P.WATCH_STYLE_LINK5

    def test_15_modules(self):
        modules = self.client.get_modules()
        self.assertEqual(len(modules), 1)
        self.assertEqual(modules[0]['base'], MAIN_BASE)
        self.assertTrue(modules[0]['build_id'].startswith(BUILD_ID[:8].hex()))


def batch_total(batch):
    return batch['total']


if __name__ == '__main__':
    unittest.main(verbosity=2)
