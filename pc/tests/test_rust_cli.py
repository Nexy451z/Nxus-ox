"""Cross-language end-to-end tests: the Rust nxus.exe against the mock Switch.

This is the real PC tool talking the real wire protocol to a peer that behaves
like the console, so the whole stack is exercised without hardware.

The CLI is spawned with stdout redirected to a file (not a pipe), which keeps it
working under sandboxes that forbid piped child stdio.
"""
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PC = os.path.dirname(HERE)
ROOT = os.path.dirname(PC)
sys.path.insert(0, PC)

from nxus import protocol as P                      # noqa: E402
from nxus.mock_switch import (MockSwitch, MONEY_ADDRESS, MAIN_BASE, DATA_BASE,  # noqa: E402
                               DATA_SIZE, HEAP_BASE)

EXE = os.path.join(PC, 'Nxus.Cli', 'target', 'release', 'nxus.exe')
SRC = os.path.join(PC, 'Nxus.Cli', 'src')


def newest_source_mtime():
    newest = 0.0
    for dirpath, _dirnames, filenames in os.walk(SRC):
        for name in filenames:
            if name.endswith('.rs'):
                newest = max(newest, os.path.getmtime(os.path.join(dirpath, name)))
    return newest


class RustCli(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.path.exists(EXE):
            raise unittest.SkipTest(f"nxus.exe not built: {EXE}")
        # Refuse to validate a BUILD THAT IS OLDER THAN THE SOURCE: these tests exist to
        # exercise the Rust client, and a stale binary passes them while the real code is
        # broken.  (Run cargo build --release first; tools/test_all.sh does.)
        if os.path.getmtime(EXE) < newest_source_mtime():
            raise AssertionError(
                f"nxus.exe is older than the newest .rs source - rebuild it "
                f"(cd {os.path.join(PC, 'Nxus.Cli')} && cargo build --release)")
        cls.tmp = tempfile.mkdtemp(prefix='nxus-rust-')
        cls.server = MockSwitch().start()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    # ---- helpers ----

    def run_nxus(self, *args, timeout=60):
        out_path = os.path.join(self.tmp, 'out.txt')
        with open(out_path, 'wb') as out:
            proc = subprocess.run(
                [EXE, '--host', '127.0.0.1', '--port', str(self.server.port), *args],
                stdout=out, stderr=subprocess.STDOUT, timeout=timeout)
        with open(out_path, 'r', encoding='utf-8', errors='replace') as handle:
            text = handle.read()
        return proc.returncode, text

    def assert_ok(self, result, needle=None):
        code, text = result
        self.assertEqual(code, 0, f"nxus exited {code}:\n{text}")
        if needle is not None:
            self.assertIn(needle, text, f"missing {needle!r} in:\n{text}")
        return text

    # ---- tests ----

    def test_01_help_without_a_console(self):
        out_path = os.path.join(self.tmp, 'help.txt')
        with open(out_path, 'wb') as out:
            code = subprocess.run([EXE, '--help'], stdout=out, stderr=subprocess.STDOUT).returncode
        with open(out_path, 'r', encoding='utf-8', errors='replace') as handle:
            text = handle.read()
        self.assertEqual(code, 0)
        self.assertIn('usage: nxus', text)

    def test_02_status(self):
        text = self.assert_ok(self.run_nxus('status'))
        self.assertIn('proto        : v1', text)
        self.assertIn('0100C3800049C000', text)

    def test_03_metadata(self):
        text = self.assert_ok(self.run_nxus('metadata'))
        self.assertIn('9d4c86e6ef74504a', text)
        self.assertIn('main nso     : 00700000', text)

    def test_04_modules_and_mappings(self):
        text = self.assert_ok(self.run_nxus('modules'))
        self.assertIn('00700000', text)
        text = self.assert_ok(self.run_nxus('mappings', '--count', '8'))
        self.assertIn('rw', text)

    def test_05_read_and_write(self):
        text = self.assert_ok(self.run_nxus('write', hex(MONEY_ADDRESS), 'u32:1234'))
        self.assertIn('wrote 4 byte(s)', text)
        text = self.assert_ok(self.run_nxus('read', hex(MONEY_ADDRESS), '4'))
        self.assertIn('d2 04 00 00', text)          # 1234 little-endian

    def test_06_scan_workflow(self):
        self.server.target.set_money(6440)
        self.assert_ok(self.run_nxus('scan', 'reset'))
        text = self.assert_ok(self.run_nxus('scan', 'begin', '6440', '--size', '4'))
        self.assertIn('1 hits', text)
        # the console's own statistics line must reach the operator: a 0-hit scan
        # is only trustworthy if it also says how much could not be read
        self.assertIn('console: scan done', text)
        self.assertIn('dropped=', text)

        self.server.target.set_money(3940)
        text = self.assert_ok(self.run_nxus('scan', 'refine', '--cmp', 'decreased'))
        self.assertIn('1 hits', text)

        text = self.assert_ok(self.run_nxus('scan', 'hits', '--limit', '5'))
        self.assertIn('42CA1DC4', text)

    def test_07_pointer_scan_and_cheat_export(self):
        text = self.assert_ok(self.run_nxus('ptrscan', hex(MONEY_ADDRESS), '--depth', '3'))
        want_root = (DATA_BASE - MAIN_BASE) + 0x1000
        self.assertIn(f'main+0x{want_root:x}', text)
        self.assertIn('+0x20', text)

        cheat_file = os.path.join(self.tmp, 'money.txt')
        text = self.assert_ok(self.run_nxus('cheat', '0', '--value', '9999999', '--out', cheat_file))
        self.assertIn('wrote', text)
        with open(cheat_file, 'r', encoding='utf-8') as handle:
            code = handle.read()
        self.assertIn(f'540F0000 {want_root:08X}', code)
        self.assertIn('540F1000 00000020', code)
        self.assertIn('640F0000 00000000 0098967F', code)

    def test_08_snapshot_capture_diff(self):
        text = self.assert_ok(self.run_nxus('snapshot', 'capture', '--slot', 'a'))
        self.assertIn('captured slot A', text)
        self.assertIn('16384 bytes', text)
        self.assert_ok(self.run_nxus('snapshot', 'capture', '--slot', 'b'))

        text = self.assert_ok(self.run_nxus('snapshot', 'diff'))
        self.assertIn('0 block(s) changed', text)

        # change two different blocks
        self.server.target.set_money(5000)
        self.server.target.heap[0x40] ^= 0xFF
        self.assert_ok(self.run_nxus('snapshot', 'capture', '--slot', 'b'))

        text = self.assert_ok(self.run_nxus('snapshot', 'diff'))
        self.assertNotIn('0 block(s) changed', text)

        text = self.assert_ok(self.run_nxus('snapshot', 'changed', '--limit', '10'))
        self.assertIn('changed', text)
        # the money record block must be in the changed set
        block = MONEY_ADDRESS - (MONEY_ADDRESS % P.SNAPSHOT_DEFAULT_BLOCK_SIZE)
        self.assertIn(f'{block:08X}', text)

    def test_09_watch_reports_the_writing_instruction(self):
        """The flagship flow: watchpoint -> pc -> main+offset, through the CLI."""
        out_path = os.path.join(self.tmp, 'watch.txt')
        with open(out_path, 'wb') as out:
            proc = subprocess.Popen(
                [EXE, '--host', '127.0.0.1', '--port', str(self.server.port),
                 'watch', hex(MONEY_ADDRESS), '--kind', 'write', '--count', '1', '--seconds', '20'],
                stdout=out, stderr=subprocess.STDOUT)
            try:
                time.sleep(1.5)                     # let it attach and arm the watchpoint
                self.assertTrue(self.server.attached, "CLI did not attach")
                self.server.simulate_watch_hit(MONEY_ADDRESS, MAIN_BASE + 0x12345, value=3940)
                proc.wait(timeout=25)
            finally:
                if proc.poll() is None:
                    proc.kill()
        with open(out_path, 'r', encoding='utf-8', errors='replace') as handle:
            text = handle.read()
        self.assertEqual(proc.returncode, 0, text)
        self.assertIn('debug mode: attached=true', text)
        self.assertIn('waiting for 1 hit(s)', text)
        self.assertIn('main+0x12345', text)
        self.assertIn('r0-r3', text)
        self.assertIn('detached', text)

    def test_11_config_sets_the_hotkey(self):
        text = self.assert_ok(self.run_nxus('config', '--hotkey', 'plus', '--hold', '300',
                                            '--watchdog', '20000'))
        self.assertIn('hotkey mask  : 0x400', text)
        self.assertIn('hotkey hold  : 300 ms', text)
        self.assertIn('watchdog     : 20000 ms', text)
        self.assertEqual(self.server.hotkey['mask'], 0x400)
        self.assertEqual(self.server.hotkey['hold_ms'], 300)
        self.assertEqual(self.server.hotkey['enabled'], 1)

        # a multi-button combo
        text = self.assert_ok(self.run_nxus('config', '--hotkey', 'ZL+ZR+PLUS'))
        self.assertIn('hotkey mask  : 0x700', text)

        text = self.assert_ok(self.run_nxus('config', '--hotkey', 'off'))
        self.assertIn('(disabled)', text)
        self.assertEqual(self.server.hotkey['enabled'], 0)

    def test_12_events_reports_the_hotkey_pause(self):
        """The controller-freezes-the-game flow, observed from the PC."""
        out_path = os.path.join(self.tmp, 'events.txt')
        with open(out_path, 'wb') as out:
            proc = subprocess.Popen(
                [EXE, '--host', '127.0.0.1', '--port', str(self.server.port),
                 'events', '--seconds', '8', '--count', '1'],
                stdout=out, stderr=subprocess.STDOUT)
            try:
                time.sleep(1.5)
                self.server.simulate_hotkey()
                proc.wait(timeout=15)
            finally:
                if proc.poll() is None:
                    proc.kill()
        with open(out_path, 'r', encoding='utf-8', errors='replace') as handle:
            text = handle.read()
        self.assertEqual(proc.returncode, 0, text)
        self.assertIn('hotkey: target paused', text)

    def test_13_events_reports_the_watchdog(self):
        out_path = os.path.join(self.tmp, 'events2.txt')
        with open(out_path, 'wb') as out:
            proc = subprocess.Popen(
                [EXE, '--host', '127.0.0.1', '--port', str(self.server.port),
                 'events', '--seconds', '8', '--count', '1'],
                stdout=out, stderr=subprocess.STDOUT)
            try:
                time.sleep(1.0)
                self.server.send_event(P.EVT['AutoResume'], b'')
                proc.wait(timeout=15)
            finally:
                if proc.poll() is None:
                    proc.kill()
        with open(out_path, 'r', encoding='utf-8', errors='replace') as handle:
            text = handle.read()
        self.assertEqual(proc.returncode, 0, text)
        self.assertIn('watchdog: target auto-resumed', text)

    def test_14_gui_renders_live_data_from_the_switch(self):
        """The GUI's data path: connect, read metadata + hex, render a frame."""
        png = os.path.join(self.tmp, 'gui-live.png')
        code, text = self.run_nxus('--screenshot', png)
        self.assertEqual(code, 0, text)
        self.assertIn('screenshot written', text)
        self.assertTrue(os.path.exists(png), "no PNG produced")
        with open(png, 'rb') as handle:
            head = handle.read(24)
        self.assertEqual(head[:8], b'\x89PNG\r\n\x1a\n', "not a PNG")
        width = int.from_bytes(head[16:20], 'big')
        height = int.from_bytes(head[20:24], 'big')
        # the window is sized for the desktop DPI, so compare against what the
        # tool reports rather than a fixed number
        import re
        match = re.search(r'\((\d+)x(\d+)\)', text)
        self.assertIsNotNone(match, f'no size in output: {text}')
        self.assertEqual((width, height), (int(match.group(1)), int(match.group(2))))
        self.assertGreaterEqual(width, 900, 'window should stay usable')
        self.assertGreaterEqual(height, 600)

    def test_15b_console_log_reaches_the_client(self):
        """The GUI's console-log view only helps if the console's statistics line
        actually arrives; the mock now emits one the way the sysmodule does."""
        # a scan makes the console log its statistics line ...
        self.assert_ok(self.run_nxus('scan', 'reset'))
        self.assert_ok(self.run_nxus('scan', 'begin', '6440', '--size', '4'))
        # ... and the client can fetch it (what the GUI's console-log button does)
        code, text = self.run_nxus('log')
        self.assertEqual(code, 0, text)
        self.assertIn('scan done', text)
        self.assertIn('dropped=', text)
        self.assertIn('hits=', text)      # a startup line would not carry a hit count

    def test_15c_pc_scan_survives_short_reads(self):
        """The console answers with fewer bytes than asked when dmnt halves a read.
        The scanner must continue from what it got, or the rest of that chunk is
        silently never examined (a wrong 'value not found' conclusion)."""
        # the heap mapping does not overlap another one, so the candidate count is
        # exactly span/4 even though every reply is short
        span = 0x20000
        hits_file = os.path.join(self.tmp, 'short.bin')
        self.server.short_read_bytes = 16 * 1024
        self.server.read_sizes.clear()
        try:
            code, text = self.run_nxus(
                'scan', 'unknown', '--size', '4', '--scope', 'custom',
                '--range', f'{hex(HEAP_BASE)}..{hex(HEAP_BASE + span)}', '--save', hits_file)
        finally:
            self.server.short_read_bytes = 0
        self.assertEqual(code, 0, text)
        self.assertEqual(int(re.search(r'(\d+) candidate', text).group(1)), span // 4,
                         'candidates were lost to a short read')
        # one request per short reply, no gap and no overlap
        self.assertEqual(len([s for s in self.server.read_sizes if s > 0]), span // (16 * 1024),
                         'the scanner did not continue from the bytes it received')

    def test_15d_day1_flow_uses_the_printed_address(self):
        """The procedure in docs/HARDWARE_DAY1.md, with the exact strings the tool
        prints: the address shown by 'scan hits' is bare hex, so write/read must
        accept it as-is (they used to refuse it, which blocked the whole flow)."""
        self.server.target.set_money(6440)
        self.assert_ok(self.run_nxus('scan', 'reset'))
        self.assert_ok(self.run_nxus('scan', 'begin', '6440', '--size', '4', '--scope', 'all'))

        self.server.target.set_money(3940)
        text = self.assert_ok(self.run_nxus('scan', 'refine', '--cmp', 'decreased'))
        self.assertIn('1 hits', text)

        text = self.assert_ok(self.run_nxus('scan', 'hits', '--limit', '5'))
        match = re.search(r'([0-9A-Fa-f]{8})\s', text)
        self.assertIsNotNone(match, f'no address in the hit list: {text[:120]}')
        address = match.group(1)

        self.assert_ok(self.run_nxus('write', address, 'u32:7777'))     # bare hex
        self.assertEqual(self.server.target.money, 7777)
        self.assert_ok(self.run_nxus('read', '0x' + address, '4'))      # and 0x-prefixed

    def test_16_scan_value_types(self):
        """Cheat Engine style value types: float, string and a ranged scan."""
        heap = 0x36000000
        self.assert_ok(self.run_nxus('scan', 'reset'))

        # float 12.5 = 0x41480000 -> little endian 00 00 48 41
        self.assert_ok(self.run_nxus('write', hex(heap + 0x200), '00 00 48 41'))
        code, text = self.run_nxus('scan', 'begin', '12.5', '--type', 'f32')
        self.assertEqual(code, 0, text)
        self.assertIn('1 hits', text)
        self.assertIn('Float', text)
        text = self.assert_ok(self.run_nxus('scan', 'hits', '--limit', '3', '--size', '4'))
        self.assertIn(f'{heap + 0x200:08X}', text)
        self.assertIn('12.5', text)

        # string scan
        self.assert_ok(self.run_nxus('scan', 'reset'))
        ball = ' '.join(f'{b:02X}' for b in b'MASTER BALL')
        self.assert_ok(self.run_nxus('write', hex(heap + 0x300), ball))
        code, text = self.run_nxus('scan', 'begin', 'MASTER BALL', '--type', 'str')
        self.assertEqual(code, 0, text)
        self.assertIn('1 hits', text)
        self.assertIn('String', text)

        # value between
        self.assert_ok(self.run_nxus('scan', 'reset'))
        self.assert_ok(self.run_nxus('write', hex(heap + 0x400), 'u32:150'))
        code, text = self.run_nxus('scan', 'begin', '100', '--cmp', 'between', '--to', '200')
        self.assertEqual(code, 0, text)
        self.assertIn('hits', text)

        # byte array with a wildcard
        self.assert_ok(self.run_nxus('scan', 'reset'))
        self.assert_ok(self.run_nxus('write', hex(heap + 0x500), 'DE AD BE EF'))
        code, text = self.run_nxus('scan', 'begin', 'DE AD ?? EF', '--type', 'bytes')
        self.assertEqual(code, 0, text)
        self.assertIn('1 hits', text)
        self.assertIn('Array of byte', text)

    def test_17_pc_side_unknown_scan(self):
        """Unknown initial value with the candidate list kept on the PC."""
        heap = 0x36000000
        hits_file = os.path.join(self.tmp, 'candidates.bin')
        self.assert_ok(self.run_nxus('scan', 'reset'))

        # plant a known baseline value so "decreased" is deterministic
        self.assert_ok(self.run_nxus('write', hex(heap + 0x800), 'u32:500'))

        # 1.5 MB is three times the mock's per-read cap (512 KB), so the client
        # must split the reads itself: without chunking the console rejects every
        # request and this returns 0 candidates.
        span = 0x180000
        self.server.read_sizes.clear()
        code, text = self.run_nxus(
            'scan', 'unknown', '--size', '4', '--scope', 'custom',
            '--range', f'{hex(heap)}..{hex(heap + span)}', '--save', hits_file)
        self.assertEqual(code, 0, text)
        self.assertIn('candidate(s)', text)
        self.assertEqual(int(re.search(r'(\d+) candidate', text).group(1)), span // 4)
        self.assertNotIn('read(s) failed', text)

        # The client must learn the advertised cap (one status round trip) and use
        # it: otherwise this test never reaches the console's limit and the chunk
        # loop it is supposed to cover stays untested.
        sizes = [s for s in self.server.read_sizes if s > 0]
        self.assertTrue(sizes, 'no read requests were recorded')
        self.assertLessEqual(max(sizes), self.server.max_read, 'requested more than advertised')
        self.assertEqual(len(sizes), -(-span // self.server.max_read),
                         f'expected {(-(-span // self.server.max_read))} reads, got {len(sizes)}')
        self.assertTrue(os.path.exists(hits_file))

        # the server advertises its read limit so the client can chunk correctly
        text = self.assert_ok(self.run_nxus('status'))
        self.assertIn('read limit   : 1048560 bytes', text)

        # the value drops -> "decreased" must leave exactly that one address
        self.assert_ok(self.run_nxus('write', hex(heap + 0x800), 'u32:100'))
        code, text = self.run_nxus('scan', 'refine', '--cmp', 'decreased', '--load', hits_file)
        self.assertEqual(code, 0, text)
        self.assertIn('1 candidate', text)
        self.assertIn(f'{heap + 0x800:08X}', text)

    def test_10_freeze_round_trip(self):
        text = self.assert_ok(self.run_nxus('freeze', hex(MONEY_ADDRESS), '--width', '4'))
        self.assertIn('freezing', text)
        text = self.assert_ok(self.run_nxus('unfreeze', hex(MONEY_ADDRESS)))
        self.assertIn('unfrozen', text)

    def test_18_ndmp_dump_and_pc_ptrscan_beyond_console_window(self):
        """Plant a pointer step at +0x2500 (> console's 0x400 window), dump to NDMP,
        and verify both live --pc and offline --dump pointer scans find it."""
        # .data+0x1200 -> heap+0x2000 (+0x2500) -> MONEY_ADDRESS - 4 (+4)
        self.assert_ok(self.run_nxus('write', hex(DATA_BASE + 0x1200), f'u32:{HEAP_BASE + 0x2000}'))
        self.assert_ok(self.run_nxus('write', hex(HEAP_BASE + 0x2000 + 0x2500), f'u32:{MONEY_ADDRESS - 4}'))

        dmp_path = os.path.join(self.tmp, 'full.dmp')
        text = self.assert_ok(self.run_nxus('dump', dmp_path, '--scope', 'writable'))
        self.assertIn('saved NDMP dump', text)
        self.assertTrue(os.path.exists(dmp_path))

        # Offline dump info (works even against an unreachable port)
        out_path = os.path.join(self.tmp, 'dmp_info.txt')
        with open(out_path, 'wb') as out:
            code = subprocess.run([EXE, '--port', '1', 'dump', 'info', dmp_path],
                                  stdout=out, stderr=subprocess.STDOUT).returncode
        with open(out_path, 'r', encoding='utf-8') as handle:
            info_text = handle.read()
        self.assertEqual(code, 0, info_text)
        self.assertIn('format       : NDMP', info_text)
        self.assertIn('0100C3800049C000', info_text)

        # Live PC pointer scan finds the +0x2500 step
        want_root = (DATA_BASE - MAIN_BASE) + 0x1200
        text = self.assert_ok(self.run_nxus(
            'ptrscan', hex(MONEY_ADDRESS), '--pc', '--depth', '3', '--max-offset', '0x3000'))
        self.assertIn(f'main+0x{want_root:x} +0x2500 +0x4', text)

        # Offline NDMP pointer scan + cheat code generation (no console connection)
        with open(out_path, 'wb') as out:
            code = subprocess.run(
                [EXE, '--port', '1', 'ptrscan', hex(MONEY_ADDRESS),
                 '--dump', dmp_path, '--module', hex(MAIN_BASE),
                 '--depth', '3', '--max-offset', '0x3000', '--cheat-value', '9999999'],
                stdout=out, stderr=subprocess.STDOUT).returncode
        with open(out_path, 'r', encoding='utf-8') as handle:
            offline_text = handle.read()
        self.assertEqual(code, 0, offline_text)
        self.assertIn(f'main+0x{want_root:x} +0x2500 +0x4', offline_text)
        self.assertIn('540F1000 00002500', offline_text)
        self.assertIn('640F0000 00000000 0098967F', offline_text)

    def test_19_pc_scan_heap_scope_excludes_module_data(self):
        """Scope::Heap on the PC scanner must exclude module .data (type=4),
        whereas Scope::Writable includes both .data and heap."""
        text_heap = self.assert_ok(self.run_nxus('scan', 'unknown', '--size', '4', '--scope', 'heap'))
        text_rw = self.assert_ok(self.run_nxus('scan', 'unknown', '--size', '4', '--scope', 'writable'))
        cnt_heap = int(re.search(r'(\d+) candidate', text_heap).group(1))
        cnt_rw = int(re.search(r'(\d+) candidate', text_rw).group(1))
        self.assertEqual(cnt_rw - cnt_heap, DATA_SIZE // 4,
                         'Heap scope did not exclude module .data on PC scan')

    def test_20_compare_ge_le_different_and_scan_undo(self):
        """Verify >= (ge), <= (le), |cur-prev|==target (different), and 1-step Scan Undo
        across both console-side and PC-side (--load) scans."""
        self.server.target.set_money(5000000)
        self.assert_ok(self.run_nxus('scan', 'reset'))

        # Console scan: begin with >= 5000000, refine with different 250, refine to 0 hits, then undo
        text = self.assert_ok(self.run_nxus('scan', 'begin', '5000000', '--cmp', 'ge', '--size', '4'))
        initial_hits = int(re.search(r'(\d+) hits', text).group(1))
        self.assertGreaterEqual(initial_hits, 1)

        self.server.target.set_money(4999750)  # |4999750 - 5000000| == 250
        text = self.assert_ok(self.run_nxus('scan', 'refine', '250', '--cmp', 'different'))
        self.assertIn('1 hits', text)

        # Over-refine to 0 hits with <= 100, then undo back to 1 hit
        text = self.assert_ok(self.run_nxus('scan', 'refine', '100', '--cmp', 'le'))
        self.assertIn('0 hits', text)

        text = self.assert_ok(self.run_nxus('scan', 'undo'))
        self.assertIn('1 hits', text)

        # PC scan: save hits, refine with different, over-refine, and undo via .bak
        pc_file = os.path.join(self.tmp, 'pc_undo.bin')
        self.assert_ok(self.run_nxus('scan', 'hits', '--save', pc_file))
        self.server.target.set_money(4999800)  # |4999800 - 4999750| == 50
        text = self.assert_ok(self.run_nxus('scan', 'refine', '50', '--cmp', 'different',
                                            '--load', pc_file, '--save', pc_file))
        self.assertIn('1 candidate(s)', text)

        text = self.assert_ok(self.run_nxus('scan', 'refine', '10', '--cmp', 'le',
                                            '--load', pc_file, '--save', pc_file))
        self.assertIn('0 candidate(s)', text)

        text = self.assert_ok(self.run_nxus('scan', 'undo', '--load', pc_file))
        self.assertIn('1 candidate(s) restored', text)

    def test_23_multi_range_scan(self):
        """--scope ranges scans the union of a comma-separated range list."""
        self.server.target.set_money(4242)          # inside HEAP (MONEY_ADDRESS)
        # range A: exactly the heap record; range B: a region that holds nothing we want
        a_begin = MONEY_ADDRESS & ~0xFFF
        a_end = a_begin + 0x2000
        b_begin = DATA_BASE
        b_end = DATA_BASE + 0x100

        text = self.assert_ok(self.run_nxus(
            'scan', 'begin', '4242', '--size', '4', '--scope', 'ranges',
            '--range', f'0x{a_begin:x}..0x{a_end:x},0x{b_begin:x}..0x{b_end:x}'))
        self.assertIn('1 hits', text)
        # the value is only in range A, so the union finds it (and only it)
        hits = self.assert_ok(self.run_nxus('scan', 'hits', '--limit', '20'))
        self.assertIn(f'{MONEY_ADDRESS:08X}', hits)
        self.assertEqual(hits.count('42CA1DC4'), 1, hits)

        # a list that misses the value must find nothing
        text = self.assert_ok(self.run_nxus(
            'scan', 'begin', '4242', '--size', '4', '--scope', 'ranges',
            '--range', f'0x{b_begin:x}..0x{b_end:x}'))
        self.assertIn('0 hits', text)

    def test_24_range_list_dedup(self):
        """A duplicated/overlapping range must not report the same address twice."""
        self.server.target.set_money(31337)
        r0 = MONEY_ADDRESS & ~0xFFF
        spec = f'0x{r0:x}..0x{r0 + 0x2000:x}'
        text = self.assert_ok(self.run_nxus('scan', 'begin', '31337', '--size', '4',
                                            '--scope', 'ranges', '--range', f'{spec},{spec}'))
        self.assertIn('1 hits', text)
        hits = self.assert_ok(self.run_nxus('scan', 'hits', '--limit', '20'))
        self.assertEqual(hits.count(f'{MONEY_ADDRESS:08X}'), 1, hits)

    def test_25_range_and_pc_guards(self):
        """The guards that keep a typo from turning into a full-memory scan must work."""
        self.server.target.set_money(5150)

        def expect_failure(args, needle):
            code, text = self.run_nxus(*args)
            self.assertNotEqual(code, 0, "exit 0 for %r:\n%s" % (args, text))
            self.assertIn(needle, text.lower(), text)
            return text

        # a malformed range is refused (not silently dropped -> full scan)
        for spec in ('0x2000..0x1000', '0x1000-0x2000', '0x1000..0x1000', 'zz..yy'):
            expect_failure(('scan', 'begin', '5150', '--size', '4', '--scope', 'ranges',
                            '--range', spec), 'usage')

        # one bad element must not shrink the list to the good one
        expect_failure(('scan', 'begin', '5150', '--size', '4', '--scope', 'ranges',
                        '--range', f'0x{MONEY_ADDRESS - 0x1000:x}..0x{MONEY_ADDRESS + 0x1000:x},'
                                   f'0x{MONEY_ADDRESS - 0x1000:x}..0x{MONEY_ADDRESS - 0x2000:x}'),
                       'usage')

        # the PC-side scanner cannot honour a range list
        expect_failure(('scan', 'unknown', '--size', '4', '--scope', 'ranges',
                        '--range', f'0x{MONEY_ADDRESS - 0x1000:x}..0x{MONEY_ADDRESS + 0x1000:x}',
                        '--pc'), 'console-side only')

        # snapshot with a range list is refused (the console has no list for it)
        expect_failure(('snapshot', 'capture', '--slot', '0', '--scope', 'ranges'), 'error')

    def test_21_address_expression_evaluator(self):
        """CLI address inputs evaluate arithmetic/bitwise expressions with main and heap."""
        self.server.target.set_money(7777)
        # MONEY_ADDRESS == (heap + (MONEY_ADDRESS - HEAP_BASE - 0x1DC4) + 0x1DC0) + 4
        rec_off = MONEY_ADDRESS - HEAP_BASE - 0x1DC4
        text = self.assert_ok(self.run_nxus('read', f'(heap+0x{rec_off:x}+0x1DC0)+4', '4'))
        self.assertIn('61 1e 00 00', text)  # 7777 == 0x1E61

        # Write via main-relative arithmetic expression: main + (DATA_BASE - MAIN_BASE) + 0x1000 + 8
        expr = f'main+0x{DATA_BASE - MAIN_BASE:x}+0x1000+8'
        self.assert_ok(self.run_nxus('write', expr, 'u32:0xCAFEBABE'))
        text = self.assert_ok(self.run_nxus('read', hex(DATA_BASE + 0x1008), '4'))
        self.assertIn('be ba fe ca', text)

    def test_22_pids_attach_64bit_regs_and_disasm(self):
        """Verify process listing (pids), PID-specific attach, 64-bit x0..x28 registers, and disasm."""
        text = self.assert_ok(self.run_nxus('pids'))
        self.assertIn('0x82', text)
        self.assertIn('2 process(es)', text)

        text = self.assert_ok(self.run_nxus('attach', '--pid', '0x77'))
        self.assertIn('attached=true', text)
        self.assertEqual(self.server.attached_pid, 0x77)

        text = self.assert_ok(self.run_nxus('threads'))
        self.assertIn('0x1001', text)

        text = self.assert_ok(self.run_nxus(
            'regs', '0x1001', '--set', 'x0=0x1122334455667788,x20=0xCAFEBABE12345678'
        ))
        self.assertIn('x0  = 1122334455667788', text)
        self.assertIn('x20 = CAFEBABE12345678', text)

        # Plant AArch64 STR W1, [X0, #4] (0xB9000401) and RET (0xD65F03C0) into writable DATA_BASE
        self.assert_ok(self.run_nxus('write', hex(DATA_BASE + 0x200), 'u32:0xB9000401'))
        self.assert_ok(self.run_nxus('write', hex(DATA_BASE + 0x204), 'u32:0xD65F03C0'))
        text = self.assert_ok(self.run_nxus('disasm', hex(DATA_BASE + 0x200), '2'))
        self.assertIn('str w1, [x0, #0x4]', text)
        self.assertIn('ret', text)

        self.assert_ok(self.run_nxus('detach'))


if __name__ == '__main__':
    unittest.main(verbosity=2)


