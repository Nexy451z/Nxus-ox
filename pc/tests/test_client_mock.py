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
                               HEAP_BASE, REC_OFFSET,
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


class ScanBreakHitIsolation(unittest.TestCase):
    """Round 5 regression guard: scan hits and break hits must stay two lists.

    They are different shapes on the wire - a scan hit is (mapping, offset, value)
    and a break hit is an 11-field register snapshot - but the mock used one
    ``self.hits`` attribute for both.  As soon as a watchpoint fired inside a scan
    session, the scan reply tried to unpack hit dicts and the debug reply tried to
    read tuple keys, so "scan, attach, break hit, scan again" was broken.  Each
    test gets its own console so both call orders are checked in isolation.
    """

    def setUp(self):
        self.server = MockSwitch(watchdog_ms=100000).start()
        self.client = NxusClient('127.0.0.1', self.server.port, timeout=5.0).connect()

    def tearDown(self):
        self.client.close()
        self.server.stop()

    # ---- helpers ----

    def scan_money(self, value: int = 6440) -> dict:
        """First-pass scan that finds exactly the money address."""
        self.server.target.set_money(value)
        self.client.scan_reset()
        st = self.client.scan_begin(value, value_size=4, cmp_mode=P.CMP['NxusCmp_Equal'],
                                    scope=P.SCOPE['NxusScope_All'])
        self.assertEqual(st['scan_state'], P.SCAN_STATE['NxusScanState_Done'])
        self.assertEqual(st['hits'], 1)
        return self.client.scan_hits(0, 16)

    def fire_watchpoint(self, value: int = 3940) -> dict:
        """Attach, arm a write watchpoint on the money and let it fire."""
        st = self.client.debug_attach()
        self.assertTrue(st['attached'])
        breaks = self.client.break_set(MONEY_ADDRESS, kind=P.BREAK_KIND['NxusBp_Write'],
                                       size=4, slot=0x10)
        self.assertEqual([b['slot'] for b in breaks], [0x10])
        return self.server.simulate_watch_hit(MONEY_ADDRESS, MAIN_BASE + 0x12345, value=value)

    def assert_scan_hits_readable(self, expected_value: int) -> dict:
        """The scan reply must still decode with a break-hit list alongside it."""
        batch = self.client.scan_hits(0, 16)
        self.assertEqual(batch['count'], 1)
        self.assertEqual(batch['total'], 1)
        hit = batch['hits'][0]
        self.assertEqual(hit['address'], MONEY_ADDRESS)
        self.assertEqual(hit['offset'], REC_OFFSET + 4)      # mapping-relative
        self.assertEqual(hit['value'], expected_value)
        self.assertEqual(self.client.scan_status()['hits'], 1)
        return batch

    def assert_break_hits_readable(self, value: int) -> list:
        """The debug reply must still decode with a scan hit list alongside it."""
        hits = self.client.hit_get(8)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]['address'], MONEY_ADDRESS)
        self.assertEqual(hits[0]['pc'], MAIN_BASE + 0x12345)
        self.assertEqual(hits[0]['r'][3], value)
        # hit_count is the break-hit table, never the scan list
        self.assertEqual(self.client.debug_status()['hit_count'], 1)
        return hits

    # ---- the two orders ----

    def test_scan_then_break_hit_then_scan(self):
        """scan -> attach -> break hit -> scan: the order a GUI session uses."""
        self.scan_money(6440)
        self.fire_watchpoint(3940)

        self.assert_break_hits_readable(3940)
        self.assert_scan_hits_readable(6440)

        # a refine walks the scan list, not the break-hit dicts
        self.server.target.set_money(3940)
        st = self.client.scan_next(cmp_mode=P.CMP['NxusCmp_Decreased'])
        self.assertEqual(st['hits'], 1)
        self.assert_scan_hits_readable(3940)
        self.assert_break_hits_readable(3940)

    def test_break_hit_then_scan_then_break_hit(self):
        """Reverse order: a watchpoint session followed by a fresh scan."""
        self.fire_watchpoint(1234)
        self.assert_break_hits_readable(1234)

        self.scan_money(6440)
        self.assert_scan_hits_readable(6440)
        self.assert_break_hits_readable(1234)      # survived the scan

        self.server.target.set_money(9999999)
        st = self.client.scan_next(cmp_mode=P.CMP['NxusCmp_Increased'])
        self.assertEqual(st['hits'], 1)
        self.assert_scan_hits_readable(9999999)
        self.assert_break_hits_readable(1234)

        # the console drops break hits with the session, and only those
        self.client.debug_detach()
        self.assertEqual(self.client.hit_get(8), [])
        self.assert_scan_hits_readable(9999999)


class HitListCapMockSwitch(MockSwitch):
    """A console that reached its hit-list limit.

    The firmware stops recording at NXUS_MAX_HITS and sets NXUS_HITBATCH_TRUNCATED
    in the reply header (core/nxus_protocol.h:349) so the PC can warn instead of
    presenting a cut-off list as final.  The stock mock never fills a list - its
    ``_get_hits()`` always packs flags=0 - and mock_switch.py is out of scope for
    this change, so this subclass reproduces the console's reply at the wire
    level: same header layout, capped list, flag set.
    """

    hit_list_limit = 8              # 0 = unlimited, the stock mock's behaviour

    def _get_hits(self, payload):
        offset, count, _r0, _r1 = P.GET_HITS_REQUEST.unpack(payload)
        if not self.hit_list_limit or len(self.hits) <= self.hit_list_limit:
            return super()._get_hits(payload)
        first = min(offset, self.hit_list_limit)
        shown = max(0, min(count, self.hit_list_limit - first))
        bases = [m['base'] for m in self.target.mappings]
        body = P.HIT_BATCH_HEADER.pack(self.session_id, shown, self.hit_list_limit,
                                       self.value_size, len(bases), P.HITBATCH_TRUNCATED)
        body += b''.join(struct.pack('<Q', b) for b in bases)
        for idx, off, value in self.hits[first:first + shown]:
            body += P.HIT.pack(off, idx, self.value_type, int.from_bytes(value, 'little'))
        return body


class ScanTruncation(unittest.TestCase):
    """NXUS_HITBATCH_TRUNCATED has to survive the wire and reach client.scan_hits().

    Without it a full hit list is indistinguishable from a complete one, which is
    the "no hits for 9999999" class of bug: the user sees a short list and believes
    the search finished.
    """

    def setUp(self):
        self.server = HitListCapMockSwitch(watchdog_ms=100000).start()
        self.client = NxusClient('127.0.0.1', self.server.port, timeout=5.0).connect()

    def tearDown(self):
        self.client.close()
        self.server.stop()

    def test_hit_list_full_sets_the_truncated_flag(self):
        # the mock target's zero window between MOD0 and BUILD_ID: every aligned
        # 4-byte slot holds 0, so an Equal scan of 0 finds more than the cap.
        window_begin, window_end = MAIN_BASE + 0x0C, MAIN_BASE + 0x40
        expected = len(range(window_begin, window_end, 4))
        self.assertGreater(expected, HitListCapMockSwitch.hit_list_limit)

        self.client.scan_reset()
        st = self.client.scan_begin(0, value_size=4, cmp_mode=P.CMP['NxusCmp_Equal'],
                                    scope=P.SCOPE['NxusScope_Custom'],
                                    range_begin=window_begin, range_end=window_end)
        self.assertEqual(st['scan_state'], P.SCAN_STATE['NxusScanState_Done'])
        self.assertEqual(st['hits'], expected,
                         "the mock target's zero window changed size")

        batch = self.client.scan_hits(0, 4096)
        self.assertTrue(batch['truncated'], 'the hit-list limit was not reported')
        self.assertEqual(batch['count'], HitListCapMockSwitch.hit_list_limit)
        self.assertEqual(batch['total'], HitListCapMockSwitch.hit_list_limit)

        # scan_all_hits() must surface it too instead of pretending it is final
        hits = self.client.scan_all_hits()
        self.assertEqual(len(hits), HitListCapMockSwitch.hit_list_limit)
        self.assertTrue(self.client.last_scan_truncated)

    def test_normal_scan_is_not_truncated(self):
        self.server.target.set_money(6440)
        self.client.scan_reset()
        st = self.client.scan_begin(6440, value_size=4, cmp_mode=P.CMP['NxusCmp_Equal'],
                                    scope=P.SCOPE['NxusScope_All'])
        self.assertEqual(st['hits'], 1)

        batch = self.client.scan_hits(0, 4096)
        self.assertFalse(batch['truncated'])
        self.assertEqual(batch['count'], 1)
        self.assertEqual(batch['total'], 1)

        self.assertEqual(len(self.client.scan_all_hits()), 1)
        self.assertFalse(self.client.last_scan_truncated)


class AsyncScanE2E(unittest.TestCase):
    """MockSwitch(scan_async=True): the console scans on a worker thread.

    ScanBegin answers NxusScanState_Running with hit_count 0, ScanGetHits /
    ScanNext answer BUSY until the worker publishes Done, and only then are the
    results readable (nxus_session.c:891-919).  This path was only reached from
    the Rust CLI, which needs a built exe, so a client regression here had no
    Python-level guard.
    """

    def setUp(self):
        self.server = MockSwitch(scan_async=True, watchdog_ms=100000).start()
        self.client = NxusClient('127.0.0.1', self.server.port, timeout=5.0).connect()

    def tearDown(self):
        self.client.close()
        self.server.stop()

    def test_begin_runs_then_busy_then_done(self):
        self.server.target.set_money(6440)
        self.client.scan_reset()
        st = self.client.scan_begin(6440, value_size=4, cmp_mode=P.CMP['NxusCmp_Equal'],
                                    scope=P.SCOPE['NxusScope_All'])
        self.assertEqual(st['scan_state'], P.SCAN_STATE['NxusScanState_Running'])
        self.assertTrue(st['flags'] & P.ST['NXUS_ST_SCANNING'])
        self.assertEqual(st['hits'], 0, 'results leaked before the worker published them')

        # the worker owns the hit arrays: both readers have to answer BUSY
        with self.assertRaises(NxusError) as ctx:
            self.client.scan_hits(0, 16)
        self.assertEqual(ctx.exception.result, P.make_result(P.ERR_BUSY))

        with self.assertRaises(NxusError) as ctx:
            self.client.scan_next(cmp_mode=P.CMP['NxusCmp_Decreased'])
        self.assertEqual(ctx.exception.result, P.make_result(P.ERR_BUSY))

        # poll the way scan_wait()/the GUI does: progress climbs, then Done
        progress = [st['progress']]
        state = self.client.scan_status()
        deadline = time.time() + 5.0
        while (state['scan_state'] == P.SCAN_STATE['NxusScanState_Running']
               and time.time() < deadline):
            progress.append(state['progress'])
            state = self.client.scan_status()
        self.assertEqual(state['scan_state'], P.SCAN_STATE['NxusScanState_Done'])
        self.assertEqual(state['hits'], 1)
        self.assertEqual(progress, sorted(progress), 'progress_permille went backwards')
        self.assertLess(progress[0], state['progress'])

        hits = self.client.scan_hits(0, 16)
        self.assertEqual(batch_total(hits), 1)
        self.assertEqual(hits['hits'][0]['address'], MONEY_ADDRESS)
        self.assertEqual(hits['hits'][0]['value'], 6440)
        self.assertFalse(hits['truncated'])


def batch_total(batch):
    return batch['total']


if __name__ == '__main__':
    unittest.main(verbosity=2)
