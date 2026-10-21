"""A mock Switch running the Nxus protocol, with a synthetic MHXX-like target.

This exists so the whole wire protocol, the client and the tooling can be
developed and tested before the console arrives.  It mirrors the semantics of
switch/source/nxus_server.c, including:
  * mapping enumeration and absolute/relative hit conversion
  * first / refine scan passes with in-place compaction
  * pause + heartbeat + watchdog auto-resume (emitting NxusEvent_AutoResume)
  * error Results encoded as NXUS_MAKE_RESULT(...)
"""
from __future__ import annotations

import socket
import struct
import threading
import time

from . import protocol as P

# --- synthetic target ----------------------------------------------------

MAIN_BASE = 0x00700000
MAIN_SIZE = 0x100000
HEAP_BASE = 0x36000000
HEAP_SIZE = 0x200000
DATA_BASE = 0x00780000          # module .data/.bss (static, writable)
DATA_SIZE = 0x00020000
REC_BASE = 0x42CA0000          # the "money record" mapping, MHXX-like
REC_SIZE = 0x10000
REC_OFFSET = 0x1DC0
MONEY_ADDRESS = REC_BASE + REC_OFFSET + 4
MOD0_OFFSET = 0x8
BUILD_ID = bytes.fromhex('9d4c86e6ef74504a') + b'\x00' * 0x18


class MockTarget:
    def __init__(self, money: int = 6440):
        self.main = bytearray(MAIN_SIZE)
        self.data = bytearray(DATA_SIZE)
        self.heap = bytearray(HEAP_SIZE)
        self.rec = bytearray(REC_SIZE)

        self.main[0:4] = b'NSO0'
        self.main[MOD0_OFFSET:MOD0_OFFSET + 4] = b'MOD0'
        self.main[0x40:0x60] = BUILD_ID

        # odd values everywhere so 6440 cannot collide
        for i in range(0, HEAP_SIZE, 4):
            struct.pack_into('<I', self.heap, i, (i * 2 + 1) & 0xFFFFFFFF)
        for i in range(0, REC_SIZE, 4):
            struct.pack_into('<I', self.rec, i, (i * 2 + 1) & 0xFFFFFFFF)

        struct.pack_into('<I', self.rec, REC_OFFSET + 0, 0x64)          # id
        struct.pack_into('<i', self.rec, REC_OFFSET + 4, money)         # mZenny
        struct.pack_into('<I', self.rec, REC_OFFSET + 8, 0)
        struct.pack_into('<I', self.rec, REC_OFFSET + 12, 5000)

        # A static pointer chain, the way a real title reaches its heap:
        #   .data+0x1000 -> heap+0x100 (+0x20) -> money record (+4)
        struct.pack_into('<I', self.data, 0x1000, HEAP_BASE + 0x100)
        struct.pack_into('<I', self.heap, 0x100 + 0x20, REC_BASE + 0x1DC0)

        self.mappings = [
            dict(base=MAIN_BASE, size=MAIN_SIZE, type=3, perm=P.PERM['NXUS_PERM_R'] | P.PERM['NXUS_PERM_X'], buf=self.main),
            dict(base=DATA_BASE, size=DATA_SIZE, type=4, perm=P.PERM['NXUS_PERM_R'] | P.PERM['NXUS_PERM_W'], buf=self.data),
            dict(base=HEAP_BASE, size=HEAP_SIZE, type=5, perm=P.PERM['NXUS_PERM_R'] | P.PERM['NXUS_PERM_W'], buf=self.heap),
            dict(base=REC_BASE, size=REC_SIZE, type=5, perm=P.PERM['NXUS_PERM_R'] | P.PERM['NXUS_PERM_W'], buf=self.rec),
        ]

    @property
    def money(self) -> int:
        """The value lives in the emulated memory, so writes through the protocol
        are visible here too - exactly like the real thing."""
        return struct.unpack_from('<i', self.rec, REC_OFFSET + 4)[0]

    def set_money(self, value: int) -> None:
        struct.pack_into('<i', self.rec, REC_OFFSET + 4, value)

    def _locate(self, address: int, size: int):
        for m in self.mappings:
            if m['base'] <= address and address + size <= m['base'] + m['size']:
                return m['buf'], address - m['base']
        return None, None

    def read(self, address: int, size: int):
        buf, off = self._locate(address, size)
        if buf is None:
            return None
        return bytes(buf[off:off + size])

    def write(self, address: int, data: bytes) -> bool:
        buf, off = self._locate(address, len(data))
        if buf is None:
            return False
        buf[off:off + len(data)] = data
        return True


# --- scan helpers --------------------------------------------------------

def _load_value(raw: bytes, size: int) -> int:
    return int.from_bytes(raw[:size], 'little')


def _compare(cur: bytes, prev: bytes | None, target: int, size: int, mode: int, flags: int = 0) -> bool:
    c = _load_value(cur, size)
    if flags & P.SCAN_F['NXUS_SCAN_F_SIGNED']:
        bits = size * 8
        if c >= (1 << (bits - 1)):
            c -= (1 << bits)
    t = target
    if flags & P.SCAN_F['NXUS_SCAN_F_SIGNED'] and t >= (1 << (size * 8 - 1)):
        t -= (1 << (size * 8))
    p = _load_value(prev, size) if prev else 0
    if prev and (flags & P.SCAN_F['NXUS_SCAN_F_SIGNED']):
        bits = size * 8
        if p >= (1 << (bits - 1)):
            p -= (1 << bits)

    if mode == P.CMP['NxusCmp_Equal']:
        return c == t
    if mode == P.CMP['NxusCmp_NotEqual']:
        return c != t
    if mode == P.CMP['NxusCmp_Greater']:
        return c > t
    if mode == P.CMP['NxusCmp_Less']:
        return c < t
    if mode == P.CMP['NxusCmp_GreaterOrEqual']:
        return c >= t
    if mode == P.CMP['NxusCmp_LessOrEqual']:
        return c <= t
    if mode == P.CMP['NxusCmp_Increased']:
        return prev is not None and c > p
    if mode == P.CMP['NxusCmp_Decreased']:
        return prev is not None and c < p
    if mode == P.CMP['NxusCmp_Unchanged']:
        return prev is not None and c == p
    if mode == P.CMP['NxusCmp_Changed']:
        return prev is not None and c != p
    if mode == P.CMP['NxusCmp_Different']:
        return prev is not None and abs(c - p) == abs(t)
    return False


# --- server --------------------------------------------------------------

class MockSwitch:
    def __init__(self, host: str = '127.0.0.1', port: int = 0, watchdog_ms: int = 15000,
                 money: int = 6440):
        self.target = MockTarget(money)
        self.watchdog_ms = watchdog_ms
        self.hits: list[tuple[int, int, bytes]] = []   # (mapping_idx, offset, value bytes)
        self.chains: list[dict] = []
        self.reads = 0
        # emulated kernel debug session
        self.attached = False
        self.attached_pid = 0
        self.watch_style = P.WATCH_STYLE_LINK5
        self.breaks: list[dict] = []
        self.hits: list[dict] = []
        self.threads = [0x1001, 0x1002]
        # Two shapes on purpose.  0x1001 is the AArch64 form (SP/LR/FP live in the
        # ThreadContext header fields).  0x1002 is what a 32-bit title reports
        # (MHXX-like): the header fields are zero and the live values sit in
        # cpu_gprs[13]/[14]/[11] - exactly what nxus_debug.c:95-99 detects, and
        # what the mock has to mirror or an AArch32 hit reports sp=lr=0.
        self.regs = {
            0x1001: dict(pc=0x00712345, lr=0x00700000, sp=0x3600F000, fp=0,
                         cpsr=0x60000010, r=[0] * 13, x=[0] * 29),
            0x1002: dict(pc=0x1D7FB668, lr=0, sp=0, fp=0, cpsr=0x60000000,
                         arch32=True, gpr13=0x7084A000, gpr14=0x1B004100,
                         r=[0] * 11 + [0x70849F80, 0, 0], x=[0] * 29),
        }
        # A/B block-hash snapshots (mirrors switch/source/nxus_snapshot_srv.c)
        self.snapshots: list = [None, None]
        self.changed: list = []
        self.changed_truncated = 0
        self.hotkey = dict(mask=0, hold_ms=0, enabled=0)
        # NxusDebugConfig.auto_continue (0 = GDB-style hold, the sysmodule default;
        # 1 = resume after a hit) and the thread the console is holding
        # (NxusDebugStatus.stopped_thread_low).
        self.auto_continue = 0
        self.stopped_thread = 0
        self.value_type = P.VT_U32
        self.pattern = b''
        # mirrors NXUS_NET_BUF_SIZE - header in shared/nxus_net.h
        self.max_read = 1024 * 1024 - 16
        self.read_sizes = []              # every READ size the client asked for
        self.short_read_bytes = 0         # >0 truncates READ replies (short-read test)
        self.last_result = 0
        self.value_size = 4
        self.scan_state = P.SCAN_STATE['NxusScanState_Idle']
        self.session_id = 0
        self.progress = 0
        self.paused = False
        self.last_heartbeat = time.time()
        self.log = []
        self._running = False
        self._client_sock = None
        self._send_lock = threading.Lock()
        self.auto_resume_count = 0

        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((host, port))
        self._server.listen(1)
        self.port = self._server.getsockname()[1]

    # ---- lifecycle ----

    def start(self):
        self._running = True
        self._accept_thread = threading.Thread(target=self._accept_loop, name='mock-accept', daemon=True)
        self._accept_thread.start()
        self._tick_thread = threading.Thread(target=self._tick_loop, name='mock-tick', daemon=True)
        self._tick_thread.start()
        return self

    def stop(self):
        self._running = False
        try:
            self._server.close()
        except OSError:
            pass
        if self._client_sock is not None:
            try:
                self._client_sock.close()
            except OSError:
                pass

    # ---- networking ----

    def _accept_loop(self):
        while self._running:
            try:
                conn, _addr = self._server.accept()
            except OSError:
                return
            self._client_sock = conn
            conn.settimeout(0.2)
            try:
                self._serve(conn)
            except OSError:
                pass
            finally:
                self._client_sock = None
                try:
                    conn.close()
                except OSError:
                    pass

    def _recv_exact(self, conn, count: int):
        chunks, got = [], 0
        while got < count:
            try:
                chunk = conn.recv(count - got)
            except socket.timeout:
                if not self._running:
                    return None
                continue
            if not chunk:
                return None
            chunks.append(chunk)
            got += len(chunk)
        return b''.join(chunks)

    def _serve(self, conn):
        while self._running:
            head = self._recv_exact(conn, P.HEADER_SIZE)
            if head is None:
                return
            magic, mtype, flags, length, seq = P.HEADER.unpack(head)
            if magic != P.MAGIC:
                return
            payload = self._recv_exact(conn, length) if length else b''
            if payload is None:
                return
            response = self._handle(mtype, payload)
            self._send(conn, mtype, seq, response)

    def _send(self, conn, mtype: int, seq: int, response):
        flags, body = (response if isinstance(response, tuple) else (0, response))
        with self._send_lock:
            conn.sendall(P.pack_header(mtype, flags, len(body), seq) + body)

    def send_event(self, event_type: int, payload: bytes = b''):
        if self._client_sock is None:
            return
        with self._send_lock:
            try:
                self._client_sock.sendall(P.pack_header(event_type, P.FLAG_ASYNC, len(payload), 0) + payload)
            except OSError:
                pass

    def _tick_loop(self):
        while self._running:
            time.sleep(0.02)
            if self.paused and (time.time() - self.last_heartbeat) * 1000 > self.watchdog_ms:
                self.paused = False
                self.auto_resume_count += 1
                self.send_event(P.EVT['AutoResume'], struct.pack('<I', self.auto_resume_count))

    # ---- hardware breakpoint encoding (mirrors switch/source/nxus_debug.c) ----
    #
    # Encoding the control word here - instead of trusting whatever the client
    # sends - is what makes the mock a usable oracle: an execute breakpoint needs
    # BT=0b0001 (LINKED_INSN_ADDR_MATCH, e.g. 0x001501E1 with LBN=5) or Atmosphère
    # rejects it with 0xE801 (KernelError_InvalidCombination), and a watchpoint
    # needs LINK/LSC/BAS plus an 8-byte aligned DBGWVR.  A mock that accepted
    # anything would hide exactly the bug the hardware tests are for.

    def _style_link_slot(self) -> int:
        """nxus_debug.c:53-55 - LINK5 links to slot 5, every other style to 4."""
        return 5 if self.watch_style == P.WATCH_STYLE_LINK5 else 4

    @staticmethod
    def _hw_break_value(kind: int, address: int) -> int:
        """nxus_debug.c:61-63 - the kernel compares aligned words only: bit 2 of
        DBGWVR is ignored, and an unaligned DBGWVR loses the high BAS bits."""
        if kind == P.BREAK_KIND['NxusBp_Execute']:
            return address & ~3
        return address & ~7

    @staticmethod
    def _watch_bas(size: int, address: int) -> int:
        """nxus_debug.c:106-113 - BAS is the byte mask at bits 5..8, shifted by the
        address' offset inside the 8-byte word and clamped to the word end."""
        offset = address & 7
        bits = 8 if size == 8 else size
        if bits == 0:
            bits = 1
        if offset + bits > 8:
            bits = 8 - offset
        return (((1 << bits) - 1) << offset) << 5

    def _build_control(self, kind: int, size: int, address: int) -> int:
        """nxus_debug.c:115-150 - the control word the sysmodule programs."""
        if kind == P.BREAK_KIND['NxusBp_Execute']:
            # DBGBCR: E | BAS | BT | LBN.  BAS selects the instruction bytes, so a
            # 2-byte breakpoint at base+2 watches bytes 2..3, not 0..1.
            bas = ((0xC if address & 2 else 0x3) if size == 2 else 0xF) << 5
            return (1 << 20) | (self._style_link_slot() << 16) | bas | 1

        # DBGWCR: E | LSC | BAS | LINK.
        lsc = {P.BREAK_KIND['NxusBp_Read']: 1, P.BREAK_KIND['NxusBp_Access']: 3}.get(kind, 2) << 3
        if self.watch_style == P.WATCH_STYLE_LINK5:
            link = 5 << 16
        elif self.watch_style == P.WATCH_STYLE_LINK6:
            link = 4 << 16
        else:
            link = 0
        return 1 | lsc | self._watch_bas(size, address) | link

    def _alloc_break_slot(self, kind: int) -> int:
        """nxus_debug.c:166-179 - 0..5 for execution, 0x10..0x13 for watchpoints,
        and never the slot that holds the context-id link breakpoint."""
        base, limit = (0, 6) if kind == P.BREAK_KIND['NxusBp_Execute'] else (0x10, 4)
        link = self._style_link_slot()
        used = {b['slot'] for b in self.breaks}
        for index in range(limit):
            slot = base + index
            if slot != link and slot not in used:
                return slot
        return 0xFFFFFFFF

    # ---- thread context (mirrors nxusDebugGetRegs / recordHit) ----

    @staticmethod
    def _cpu_gprs(ctx: dict) -> list[int]:
        """cpu_gprs[0..14]: r13/r14 are kept out of the 13-entry wire `r` list, the
        way libnx keeps them out of ctx->cpu_gprs[0..12] consumers."""
        gprs = (list(ctx.get('r', [])) + [0] * 13)[:13]
        gprs.append(int(ctx.get('gpr13', 0)))
        gprs.append(int(ctx.get('gpr14', 0)))
        return gprs

    @staticmethod
    def _is_aarch32(ctx: dict) -> bool:
        """nxus_debug.c:95-99 - a 32-bit process reports sp=lr=0 in the header and
        keeps the live values in cpu_gprs[13]/[14]."""
        if ctx.get('arch32'):
            return True
        return (ctx.get('sp', 0) == 0 and ctx.get('lr', 0) == 0
                and (ctx.get('gpr13', 0) != 0 or ctx.get('gpr14', 0) != 0))

    def _thread_context(self, thread_id: int, ctx: dict) -> dict:
        """The register window nxusDebugGetRegs() hands to the PC, with the
        AArch32 remap applied (nxus_debug.c:656-674)."""
        gprs = self._cpu_gprs(ctx)
        x = (list(ctx.get('x', [])) + [0] * 29)[:29]
        for i in range(13):
            if x[i] == 0 and gprs[i] != 0:
                x[i] = gprs[i]
        if self._is_aarch32(ctx):
            sp, lr, fp = gprs[13], gprs[14], gprs[11]
            for i in range(15):
                x[i] = gprs[i]
        else:
            sp, lr, fp = ctx.get('sp', 0), ctx.get('lr', 0), ctx.get('fp', 0)
        return dict(thread_id=thread_id, pc=ctx['pc'], lr=lr, sp=sp, fp=fp,
                    cpsr=ctx.get('cpsr', 0), r=gprs[:13], x=x)

    # ---- command handling ----

    def _error(self, desc: int):
        return (P.FLAG_ERROR, struct.pack('<i', struct.unpack('<i', struct.pack('<I', P.make_result(desc)))[0]))

    def _status(self) -> bytes:
        flags = 0
        if self.paused:
            flags |= P.ST['NXUS_ST_PAUSED']
        if self.scan_state == P.SCAN_STATE['NxusScanState_Running']:
            flags |= P.ST['NXUS_ST_SCANNING']
        if self.attached:
            flags |= P.ST['NXUS_ST_DEBUG_MODE'] | P.ST['NXUS_ST_DEBUG_ATTACHED']
        if self.stopped_thread:
            flags |= P.ST['NXUS_ST_DEBUG_STOPPED']
        flags |= P.ST['NXUS_ST_HAS_PROCESS']
        return P.STATUS.pack(P.PROTO_VERSION, P.MODE['NXUS_MODE_DMNT'], flags, self.scan_state,
                             0x1234, 0x0100C3800049C000, MAIN_BASE, MAIN_SIZE,
                             len(self.hits), self.progress, 0, 1234,
                             0, 8 * 1024 * 1024, self.max_read)

    def _handle(self, cmd: int, payload: bytes):
        if cmd == P.CMD['Nop']:
            return b''
        if cmd == P.CMD['Heartbeat']:
            self.last_heartbeat = time.time()
            return b''
        if cmd == P.CMD['Pause']:
            self.paused = True
            self.last_heartbeat = time.time()
            return b''
        if cmd == P.CMD['Resume']:
            self.paused = False
            return b''
        if cmd in (P.CMD['GetStatus'], P.CMD['ScanStatus']):
            return self._status()
        if cmd == P.CMD['GetMetadata']:
            return P.PROCESS_METADATA.pack(0x1234, 0x0100C3800049C000,
                                           MAIN_BASE, MAIN_SIZE, HEAP_BASE, HEAP_SIZE,
                                           0, 0, 0, 0, BUILD_ID)
        if cmd == P.CMD['GetMappingCount']:
            return struct.pack('<Q', len(self.target.mappings))
        if cmd == P.CMD['GetMappings']:
            offset, max_count, _res = P.MAPPINGS_REQUEST.unpack(payload)
            out = b''
            for m in self.target.mappings[offset:offset + max_count]:
                out += P.MEMORY_INFO.pack(m['base'], m['size'], m.get('type', 2), 0, m['perm'], 0, 0, 0)
            return out
        if cmd == P.CMD['Query']:
            address = int.from_bytes(payload[:8], 'little')
            for m in self.target.mappings:
                if m['base'] <= address < m['base'] + m['size']:
                    return P.MEMORY_INFO.pack(m['base'], m['size'], m.get('type', 2), 0, m['perm'], 0, 0, 0)
            return P.MEMORY_INFO.pack(0, 0, 0, 0, 0, 0, 0, 0)
        if cmd == P.CMD['Read']:
            address, size, _res = P.READ_REQUEST.unpack(payload)
            self.read_sizes.append(size)      # lets tests prove the cap is used
            # the real sysmodule refuses anything larger than half its net buffer;
            # mirroring that here is what makes the PC-side scanner testable
            if size == 0 or size > self.max_read:
                return self._error(P.ERR_TOO_LARGE)
            data = self.target.read(address, size)
            if data is None:
                return self._error(P.ERR_BAD_STATE)
            if self.short_read_bytes and len(data) > self.short_read_bytes:
                # the real sysmodule halves a read dmnt refuses, so a reply may be
                # shorter than the request
                data = data[:self.short_read_bytes]
            return data
        if cmd == P.CMD['Write']:
            address, size, _res = P.WRITE_HEADER.unpack_from(payload, 0)
            data = payload[P.WRITE_HEADER.size:P.WRITE_HEADER.size + size]
            if not self.target.write(address, data):
                return self._error(P.ERR_BAD_STATE)
            return b''
        if cmd == P.CMD['GetModules']:
            out = b''
            for i, m in enumerate(self.target.mappings):
                head = self.target.read(m['base'], 0x200)
                if head and head.find(b'MOD0') >= 0:
                    out += P.MODULE_INFO.pack(m['base'], m['size'], head[0x40:0x60],
                                              f"mod{i}".encode() + b'\x00' * 12)
            return out
        if cmd == P.CMD['GetProcesses']:
            return struct.pack('<2Q', 0x51, 0x82)
        if cmd == P.CMD['SnapshotCapture']:
            return self._snapshot_capture(payload)
        if cmd == P.CMD['SnapshotDiff']:
            from_slot, to_slot = 0, 1
            if len(payload) >= P.SNAPSHOT_DIFF_REQUEST.size:
                from_slot, to_slot, _a, _b = P.SNAPSHOT_DIFF_REQUEST.unpack(payload)
            return self._snapshot_diff(from_slot, to_slot)
        if cmd == P.CMD['SnapshotChanged']:
            offset, count = 0, 1024
            if len(payload) >= P.GET_HITS_REQUEST.size:
                offset, count, _a, _b = P.GET_HITS_REQUEST.unpack(payload)
            subset = self.changed[offset:offset + count]
            return b''.join(P.CHANGED_BLOCK.pack(c['address'], c['size'], c['flags']) for c in subset)
        if cmd == P.CMD['DebugAttach']:
            req_pid = int.from_bytes(payload[:8], 'little') if len(payload) >= 8 else 0
            self.attached = True
            self.attached_pid = req_pid if req_pid != 0 else 0x82
            self.stopped_thread = 0
            self.last_result = 0
            return self._debug_status()
        if cmd == P.CMD['DebugDetach']:
            self.attached = False
            self.breaks = []
            self.stopped_thread = 0
            return b''
        if cmd == P.CMD['DebugStatus']:
            return self._debug_status()
        if cmd == P.CMD['BreakSet']:
            slot, kind, size, ctrl, address = P.BREAK_REQUEST.unpack(payload)
            if not self.attached:
                return self._error(P.ERR_NOT_ATTACHED)
            # nxusDebugSetBreak() (nxus_debug.c:515-560): normalise the slot for the
            # kind and build the control word when the client leaves it 0.  An
            # execute breakpoint (kind == NxusBp_Execute) is legal and lives in
            # slots 0..5; it must never take the context-id link slot, and its
            # DBGBVR value is the address truncated to 4 bytes.
            size = size or 4
            if kind == P.BREAK_KIND['NxusBp_Execute']:
                if slot >= 6 or slot == self._style_link_slot():
                    slot = self._alloc_break_slot(kind)
            elif slot < 0x10 or slot > 0x13:
                slot = self._alloc_break_slot(kind)
            if slot == 0xFFFFFFFF:
                return self._error(P.ERR_BUSY)
            if not ctrl:
                ctrl = self._build_control(kind, size, address)
            self.breaks = [b for b in self.breaks if b['slot'] != slot]
            self.breaks.append(dict(slot=slot, kind=kind, size=size, enabled=1,
                                    address=address, ctrl=ctrl))
            return self._break_list()
        if cmd == P.CMD['BreakClear']:
            slot = int.from_bytes(payload[:4], 'little')
            self.breaks = [b for b in self.breaks if b['slot'] != slot]
            return b''
        if cmd == P.CMD['BreakList']:
            return self._break_list()
        if cmd == P.CMD['DebugContinue']:
            self.stopped_thread = 0
            return b''
        if cmd == P.CMD['DebugStep']:
            # nxusDebugStep(): single-step the held thread and keep holding it, so
            # the PC can inspect the instruction that just retired.
            thread_id = int.from_bytes(payload[:8], 'little') if len(payload) >= 8 else 0
            if thread_id == 0:
                thread_id = self.stopped_thread or (self.threads[0] if self.threads else 0)
            ctx = self.regs.get(thread_id)
            if ctx is not None:
                thumb = ctx.get('arch32') and (ctx.get('cpsr', 0) & 0x20)
                ctx['pc'] = (ctx['pc'] + (2 if thumb else 4)) & 0xFFFFFFFFFFFFFFFF
            self.stopped_thread = thread_id
            return b''
        if cmd == P.CMD['ThreadList']:
            return b''.join(P.THREAD_ENTRY.pack(t, 1, 0x2C, 0, 0) for t in self.threads)
        if cmd == P.CMD['RegsGet']:
            thread_id = int.from_bytes(payload[:8], 'little')
            ctx = self.regs.get(thread_id)
            if ctx is None:
                return self._error(P.ERR_BAD_STATE)
            wire = self._thread_context(thread_id, ctx)
            return P.THREAD_CONTEXT.pack(wire['thread_id'], wire['pc'], wire['lr'],
                                         wire['sp'], wire['fp'], wire['cpsr'],
                                         *wire['r'], 0, *wire['x'])
        if cmd == P.CMD['RegsSet']:
            values = P.THREAD_CONTEXT.unpack(payload)
            r_vals = list(values[6:19])
            flags = values[19]
            x_vals = list(values[20:49])
            if not (flags & 1):
                for i in range(13):
                    if x_vals[i] == 0 and r_vals[i] != 0:
                        x_vals[i] = r_vals[i]
            for i in range(13):
                r_vals[i] = x_vals[i] & 0xFFFFFFFF
            prev = self.regs.get(values[0], {})
            if self._is_aarch32(prev):
                # nxus_debug.c:704-711 - a 32-bit core restores r13/r14/r11, not the
                # header fields, so the SP/LR/FP the user edited must land there and
                # the header fields stay zero like libnx reports them.
                entry = dict(pc=values[1], lr=0, sp=0, fp=0, cpsr=values[5],
                             r=r_vals, x=x_vals, arch32=True,
                             gpr13=values[3] & 0xFFFFFFFF,
                             gpr14=values[2] & 0xFFFFFFFF)
                entry['r'][11] = values[4] & 0xFFFFFFFF
                entry['x'][11] = values[4] & 0xFFFFFFFF
                entry['x'][13] = values[3] & 0xFFFFFFFF
                entry['x'][14] = values[2] & 0xFFFFFFFF
            else:
                entry = dict(pc=values[1], lr=values[2], sp=values[3], fp=values[4],
                             cpsr=values[5], r=r_vals, x=x_vals)
            self.regs[values[0]] = entry
            return b''
        if cmd == P.CMD['HitGet']:
            return self._hit_list()
        if cmd == P.CMD['HitClear']:
            self.hits = []
            return b''
        if cmd == P.CMD['PtrScanBegin']:
            return self._ptr_scan(payload)
        if cmd == P.CMD['PtrScanGet']:
            return self._chain_list()
        if cmd == P.CMD['CheatExport']:
            index, value_width, flags, _res, value = P.CHEAT_EXPORT_REQUEST.unpack(payload)
            if index >= len(self.chains):
                return self._error(P.ERR_BAD_STATE)
            is_32bit = bool(flags & P.CHEAT_F_32BIT)
            load = '540F' if is_32bit else '580F'
            chain = self.chains[index]
            text = "[Nxus]\n"
            text += f"{load}0000 {chain['root_offset']:08X}\n"
            for step in chain['steps']:
                text += f"{load}1000 {step:08X}\n"
            if chain['final_offset']:
                text += f"780F0000 {chain['final_offset']:08X}\n"
            width = {1: 1, 2: 2, 4: 4, 8: 8}.get(value_width, 4)
            text += f"6{width:X}0F0000 {(value >> 32) & 0xFFFFFFFF:08X} {value & 0xFFFFFFFF:08X}\n"
            return text.encode()
        if cmd == P.CMD['ScanBegin']:
            return self._scan_begin(payload)
        if cmd == P.CMD['ScanNext']:
            return self._scan_next(payload)
        if cmd == P.CMD['ScanCancel']:
            if self.scan_state == P.SCAN_STATE['NxusScanState_Running']:
                self.scan_state = P.SCAN_STATE['NxusScanState_Cancelled']
            return b''
        if cmd == P.CMD['ScanReset']:
            self.hits = []
            self.prev_scan_hits = []
            self.scan_state = P.SCAN_STATE['NxusScanState_Idle']
            self.progress = 0
            return b''
        if cmd == P.CMD['ScanUndo']:
            if not getattr(self, 'prev_scan_hits', None):
                return self._error(P.ERR_BAD_STATE)
            self.hits = list(self.prev_scan_hits)
            self.prev_scan_hits = []
            self.scan_state = P.SCAN_STATE['NxusScanState_Done']
            self.progress = 1000
            return self._status()
        if cmd == P.CMD['ScanGetHits']:
            return self._get_hits(payload)
        if cmd == P.CMD['FrozenList']:
            return b''
        if cmd == P.CMD['FrozenEnable']:
            address, width, _res = P.FROZEN_REQUEST.unpack(payload)
            if self.attached:
                # the real sysmodule refuses: freezing is a dmnt cheat-VM feature and
                # dmnt is closed while a debug session is held
                return self._error(P.ERR_BUSY)
            if width not in (1, 2, 4, 8):
                return self._error(P.ERR_BAD_STATE)
            data = self.target.read(address, width)      # honour the width, not a fixed 4
            value = int.from_bytes(data, 'little') if data else 0
            return struct.pack('<Q', value)
        if cmd == P.CMD['FrozenDisable']:
            return b''
        if cmd == P.CMD['Config']:
            cfg = P.CONFIG.unpack_from(payload, 0)      # payload may carry a debug tail
            self.hotkey = dict(mask=cfg[0], hold_ms=cfg[1], enabled=cfg[2])
            if cfg[4]:
                self.watchdog_ms = cfg[4]
            if len(payload) >= P.CONFIG.size + P.DEBUG_CONFIG.size:
                style, auto, _a, _b = P.DEBUG_CONFIG.unpack_from(payload, P.CONFIG.size)
                self.watch_style = style
                self.auto_continue = auto
            return P.CONFIG.pack(*cfg)
        if cmd == P.CMD['LogGet']:
            return '\n'.join(self.log).encode()
        return self._error(P.ERR_NOT_IMPLEMENTED)

    # ---- snapshots (emulated) ----

    @staticmethod
    def _hash64(data: bytes) -> int:
        h = 0xCBF29CE484222325
        for byte in data:
            h ^= byte
            h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
        return h

    def _snapshot_summary(self, slot: int) -> bytes:
        snap = self.snapshots[slot]
        count = len(snap['hashes']) if snap else 0
        block_size = snap['block_size'] if snap else 0
        regions = snap['regions'] if snap else 0
        return P.SNAPSHOT_SUMMARY.pack(slot, count, len(self.changed), block_size, regions,
                                       self.changed_truncated, 0, 0)

    def _snapshot_capture(self, payload: bytes) -> bytes:
        slot, block_size, scope, _res, range_begin, range_end = P.SNAPSHOT_REQUEST.unpack(payload)
        if slot > 1:
            return self._error(P.ERR_BAD_STATE)
        block_size = block_size or P.SNAPSHOT_DEFAULT_BLOCK_SIZE

        if scope == P.SCOPE['NxusScope_Ranges']:
            # the console has no range list for snapshots (nxusSessionPrepareRegions
            # rejects it): returning success here would hide a real BAD_STATE
            return self._error(P.ERR_BAD_STATE)

        hashes, addresses = [], []
        regions = self._regions(scope, range_begin, range_end)
        for _idx, m, begin, stop in regions:
            map_base = m['base']
            block = begin - (begin % block_size)
            while block < stop:
                start = max(block, begin)
                end = min(block + block_size, stop)
                addresses.append(block)
                hashes.append(self._hash64(bytes(m['buf'][start - map_base:end - map_base])))
                block += block_size

        self.snapshots[slot] = dict(hashes=hashes, addresses=addresses, block_size=block_size,
                                    regions=len(regions))
        return self._snapshot_summary(slot)

    def _snapshot_diff(self, from_slot: int, to_slot: int) -> bytes:
        a, b = self.snapshots[from_slot], self.snapshots[to_slot]
        if a is None or b is None or a['block_size'] != b['block_size']:
            return self._error(P.ERR_BAD_STATE)

        changed, i, j = [], 0, 0
        while i < len(a['addresses']) or j < len(b['addresses']):
            if i < len(a['addresses']) and (j >= len(b['addresses']) or a['addresses'][i] < b['addresses'][j]):
                changed.append(dict(address=a['addresses'][i], size=0, flags=P.CHANGE_VANISHED))
                i += 1
                continue
            if j < len(b['addresses']) and (i >= len(a['addresses']) or b['addresses'][j] < a['addresses'][i]):
                changed.append(dict(address=b['addresses'][j], size=0, flags=P.CHANGE_APPEARED))
                j += 1
                continue
            if a['hashes'][i] != b['hashes'][j]:
                changed.append(dict(address=b['addresses'][j], size=b['block_size'],
                                    flags=P.CHANGE_CHANGED))
            i += 1
            j += 1

        self.changed = changed
        self.changed_truncated = 0
        return self._snapshot_summary(to_slot)

    # ---- debug session (emulated) ----

    def _debug_status(self) -> bytes:
        return P.DEBUG_STATUS.pack(1 if self.attached else 0, self.watch_style,
                                   len(self.breaks), len(self.hits), len(self.threads),
                                   self.last_result, self.auto_continue,
                                   self.stopped_thread & 0xFFFFFFFF)

    def _break_list(self) -> bytes:
        return b''.join(P.BREAK_ENTRY.pack(b['slot'], b['kind'], b['size'], b['enabled'],
                                           b['address'], b['ctrl']) for b in self.breaks)

    def _hit_list(self) -> bytes:
        out = b''
        for h in reversed(self.hits):          # newest first, like the sysmodule
            out += self._pack_hit(h)
        return out

    def simulate_hotkey(self):
        """Pretend the controller combo fired: the sysmodule pauses and tells us."""
        self.paused = True
        self.last_heartbeat = time.time()
        self.send_event(P.EVT['HotkeyPaused'], b'')

    def _match_break(self, address: int, kind=None, slot=None):
        """recordHit()'s match rule (nxus_debug.c:211-226): the exception reports the
        value the breakpoint was programmed with, so compare the aligned word, and
        report the user's address for a data breakpoint."""
        for b in self.breaks:
            if not b.get('enabled'):
                continue
            if kind is not None and b['kind'] != kind:
                continue
            if slot is not None and b['slot'] != slot:
                continue
            if self._hw_break_value(b['kind'], b['address']) == \
                    self._hw_break_value(b['kind'], address):
                return b
        return None

    @staticmethod
    def _pack_hit(hit: dict) -> bytes:
        regs = (list(hit['r']) + [0] * 13)[:13]
        return P.BREAK_HIT.pack(hit['index'], hit['kind'], hit['slot'], hit['thread_id_low'],
                                hit['address'], hit['pc'], hit['lr'], hit['sp'], hit['cpsr'],
                                *regs, hit['tick'])

    def simulate_hit(self, address: int, pc: int, value: int = 0, kind=None,
                     slot=None, thread_id: int = 0x1001):
        """Pretend the target stopped on one of the armed breakpoints.

        `kind=None` / `slot=None` mean "whatever is armed for this address", the way
        the kernel reports it.  The register window comes from the thread context,
        and for an AArch32 thread SP/LR come from cpu_gprs[13]/[14] - the header
        fields are zero for a 32-bit title (nxus_debug.c:233-240).
        """
        bp = self._match_break(address, kind, slot)
        if bp is not None:
            slot, kind = bp['slot'], bp['kind']
        if kind is None:
            kind = P.BREAK_KIND['NxusBp_Write']
        if slot is None:
            slot = 0x10

        if kind == P.BREAK_KIND['NxusBp_Execute']:
            hit_address = self._hw_break_value(kind, address)   # DBGBVR = addr & ~3
        else:
            hit_address = bp['address'] if bp is not None else address

        ctx = self.regs.get(thread_id)
        if ctx is None:
            r_vals, sp, lr, cpsr = [0] * 13, 0x3600F000, pc - 4, 0x60000010
        else:
            wire = self._thread_context(thread_id, ctx)
            r_vals, sp, lr, cpsr = list(wire['r']), wire['sp'], wire['lr'], wire['cpsr']
        if value:
            r_vals[3] = value & 0xFFFFFFFF       # r3 held the value being written

        hit = dict(index=len(self.hits), kind=kind, slot=slot, thread_id_low=thread_id,
                   address=hit_address, pc=pc, lr=lr, sp=sp, cpsr=cpsr,
                   r=r_vals, tick=12345)
        self.hits.append(hit)
        self.send_event(P.EVT['BreakHit'], self._pack_hit(hit))
        if self.auto_continue == 0:
            # auto_continue=0: the console holds the thread at the trapping
            # instruction and reports the stop separately (NxusEvent_DebugStopped).
            # Sync the thread context first so a regs read agrees with the event.
            if ctx is not None:
                ctx['pc'] = pc
            self.stopped_thread = thread_id
            self.send_event(P.EVT['DebugStopped'],
                            P.DEBUG_STOP.pack(thread_id, pc, hit_address, kind, slot))
        return hit

    def simulate_watch_hit(self, address: int, pc: int, value: int, kind: int = 1,
                           slot: int = 0x10, thread_id: int = 0x1001):
        """Pretend the target just wrote to a watched address."""
        return self.simulate_hit(address, pc, value, kind=kind, slot=slot,
                                 thread_id=thread_id)

    def simulate_exec_hit(self, address: int, thread_id: int = 0x1001, slot=None,
                          value: int = 0):
        """Pretend the core reached an execute breakpoint (kind 0, DBGBVR = addr&~3)."""
        return self.simulate_hit(address, self._hw_break_value(
            P.BREAK_KIND['NxusBp_Execute'], address), value,
            kind=P.BREAK_KIND['NxusBp_Execute'], slot=slot, thread_id=thread_id)

    # ---- pointer scan ----
    # Deliberately an independent implementation of the same algorithm as
    # core/nxus_ptrscan.c: agreement between the two is the cross-check.

    def _mapped(self, address: int, width: int) -> bool:
        for m in self.target.mappings:
            if m['base'] <= address and address + width <= m['base'] + m['size']:
                return True
        return False

    def _read_target(self, address: int, size: int):
        return self.target.read(address, size)

    def _ptr_scan(self, payload: bytes):
        target, module_base, max_depth, max_offset, max_results, value_width = \
            P.PTRSCAN_REQUEST.unpack(payload)
        max_depth = max_depth or 3
        max_offset = max_offset or 0x1000
        max_results = max_results or 64
        width = 8 if value_width == 8 else 4

        module_end = module_base + MAIN_SIZE
        statics = [m for m in self.target.mappings
                   if (m['perm'] & P.PERM['NXUS_PERM_R']) and (m['perm'] & P.PERM['NXUS_PERM_W'])
                   and module_base <= m['base'] and m['base'] + m['size'] <= module_end]

        chains: list[dict] = []
        self.reads = 0

        def walk(reg: int, depth: int, steps: list[int], root_offset: int):
            if len(chains) >= max_results:
                return
            if reg <= target and target - reg <= max_offset:
                chains.append(dict(root_offset=root_offset, steps=list(steps),
                                   final_offset=target - reg))
                return
            if depth >= max_depth:
                return
            data = self._read_target(reg, 0x400)
            self.reads += 1
            if data is None:
                return
            for off in range(0, len(data) - width + 1, width):
                v = int.from_bytes(data[off:off + width], 'little')
                if v == 0 or v == reg or not self._mapped(v, width):
                    continue
                steps.append(off)
                walk(v, depth + 1, steps, root_offset)
                steps.pop()

        for m in statics:
            for off in range(0, m['size'] - width + 1, width):
                v = int.from_bytes(m['buf'][off:off + width], 'little')
                if v == 0 or not self._mapped(v, width):
                    continue
                self.reads += 1
                walk(v, 1, [], m['base'] - module_base + off)

        self.chains = chains
        return self._chain_list()

    def _chain_list(self) -> bytes:
        header = P.PTR_CHAIN_LIST_HEADER.pack(len(self.chains), len(self.chains), 0, 0)
        body = header
        for c in self.chains:
            steps = list(c['steps']) + [0] * (P.NXUS_PTRSCAN_MAX_DEPTH - len(c['steps']))
            body += P.PTR_CHAIN.pack(c['root_offset'], c['final_offset'], len(c['steps']), 0, *steps)
        return body

    # ---- scanning ----

    def _regions(self, scope: int, range_begin: int, range_end: int, ranges=None):
        """Mirrors nxusBuildRegions() in core/nxus_scan.c: the read range is clipped
        to the scope while the hit offset stays relative to the MAPPING base.

        Clipping here (instead of taking whole mappings) is what lets the E2E tests
        catch a regression that would make the PC resolve hits to wrong addresses.
        """
        out = []
        for idx, m in enumerate(self.target.mappings):
            if not (m['perm'] & P.PERM['NXUS_PERM_R']) or m['size'] == 0:
                continue
            begin = m['base']
            end = m['base'] + m['size']

            if scope == P.SCOPE['NxusScope_Main']:
                if m['base'] != MAIN_BASE:
                    continue
                begin = max(begin, MAIN_BASE)
                end = min(end, MAIN_BASE + MAIN_SIZE)
            elif scope == P.SCOPE['NxusScope_Heap']:
                if not (m['perm'] & P.PERM['NXUS_PERM_W']):
                    continue
                if m.get('type', 0) not in (0, 5):
                    continue
            elif scope == P.SCOPE['NxusScope_Writable']:
                if not (m['perm'] & P.PERM['NXUS_PERM_W']):
                    continue
            elif scope == P.SCOPE['NxusScope_Tls']:
                if m.get('type', 0) != 0x0C:
                    continue
            elif scope == P.SCOPE['NxusScope_Ranges']:
                # one region per (mapping, range) intersection - same rule as the
                # console's nxusBuildRegionsMulti()
                if not ranges:
                    continue
                pieces = []
                for r_begin, r_end in ranges:
                    if r_end <= r_begin:
                        continue
                    b = max(m['base'], r_begin)
                    e = min(m['base'] + m['size'], r_end)
                    if e > b:
                        pieces.append((b, e))
                if not pieces:
                    continue
                # sorted + merged, like nxusBuildRegionsMulti(): a duplicated range
                # must not report the same address twice
                pieces.sort()
                merged = [pieces[0]]
                for b, e in pieces[1:]:
                    lb, le = merged[-1]
                    if b <= le:
                        merged[-1] = (lb, max(le, e))
                    else:
                        merged.append((b, e))
                out.extend((idx, m, b, e) for b, e in merged)
                continue
            elif scope == P.SCOPE['NxusScope_Custom']:
                if range_end <= range_begin:
                    continue
                if end <= range_begin or begin >= range_end:
                    continue
                begin = max(begin, range_begin)
                end = min(end, range_end)

            if end <= begin:
                continue
            out.append((idx, m, begin, end))
        return out

    def _scan_begin(self, payload: bytes):
        kind, value_size, cmp_mode, scope, range_begin, range_end, target, target2, _chunk, flags = \
            P.SCAN_REQUEST.unpack_from(payload, 0)
        if value_size not in (1, 2, 4, 8):
            return self._error(P.ERR_UNSUPPORTED)

        # optional tail: range list (NXUS_SCAN_F_RANGES), then value type + pattern
        tail = P.SCAN_REQUEST.size
        ranges = []
        if flags & P.SCAN_F_RANGES:
            count, _res = P.RANGE_LIST_HEADER.unpack_from(payload, tail)
            count = min(count, P.MAX_SCAN_RANGES)
            tail += P.RANGE_LIST_HEADER.size
            for i in range(count):
                begin, end = P.RANGE_ENTRY.unpack_from(payload, tail + i * P.RANGE_ENTRY.size)
                ranges.append((begin, end))
            tail += count * P.RANGE_ENTRY.size

        value_type = P.VT_U32
        pattern = b''
        if len(payload) >= tail + P.SCAN_EXT.size:
            value_type, pattern_len, _eps, _res = P.SCAN_EXT.unpack_from(payload, tail)
            start = tail + P.SCAN_EXT.size
            pattern = bytes(payload[start:start + pattern_len])

        if scope == P.SCOPE['NxusScope_Ranges'] and not ranges:
            # the console rejects this instead of scanning nothing (nxus_server.c)
            return self._error(P.ERR_BAD_STATE)

        self.value_size = value_size
        self.value_type = value_type
        self.pattern = pattern
        self.hits = []
        self.prev_scan_hits = []
        self.progress = 0
        self.session_id += 1

        for idx, m, begin, end in self._regions(scope, range_begin, range_end, ranges):
            # hits carry MAPPING-relative offsets (as on the console): the window is
            # clipped, the offsets are not
            base_off = begin - m['base']
            data = bytes(m['buf'][base_off:end - m['base']])

            if value_type == P.VT_STRING and pattern:
                # string scan: byte-for-byte search
                needle = pattern
                for off in range(0, len(data) - len(needle) + 1):
                    if data[off:off + len(needle)] == needle:
                        self.hits.append((idx, base_off + off, needle))
                continue

            if value_type in (P.VT_BYTES, P.VT_BINARY) and pattern:
                # byte array search, honouring ?? wildcards
                if flags & P.SCAN_F_WILDCARD:
                    start2 = P.SCAN_REQUEST.size + P.SCAN_EXT.size + len(pattern)
                    mask = bytes(payload[start2:start2 + len(pattern)])
                else:
                    mask = b'\xff' * len(pattern)
                width = len(pattern)
                for off in range(0, len(data) - width + 1):
                    ok = True
                    for i, want in enumerate(pattern):
                        if ((data[off + i] ^ want) & mask[i]) != 0:
                            ok = False
                            break
                    if ok:
                        self.hits.append((idx, base_off + off, pattern))
                continue

            step = value_size
            for off in range(0, len(data) - step + 1, step):
                cur = data[off:off + step]
                if _compare(cur, None, target, value_size, cmp_mode, flags):
                    self.hits.append((idx, base_off + off, cur))

        self.progress = 1000
        self.scan_state = P.SCAN_STATE['NxusScanState_Done']
        # the real sysmodule logs its statistics; mirror the line the GUI shows
        self.log.append(f"scan done: hits={len(self.hits)} dropped=0 retries=0 reads=1")
        return self._status()

    def _scan_next(self, payload: bytes):
        _kind, _vs, cmp_mode, _scope, _rb, _re, target, _t2, _chunk, flags = \
            P.SCAN_REQUEST.unpack_from(payload, 0)
        self.prev_scan_hits = list(self.hits)
        kept = []
        for idx, off, prev in self.hits:
            m = self.target.mappings[idx]
            cur = bytes(m['buf'][off:off + self.value_size])
            if _compare(cur, prev, target, self.value_size, cmp_mode, flags):
                kept.append((idx, off, cur))
        self.hits = kept
        self.progress = 1000
        self.scan_state = P.SCAN_STATE['NxusScanState_Done']
        self.log.append(f"scan done: hits={len(self.hits)} dropped=0 retries=0 reads=1")
        return self._status()

    def _get_hits(self, payload: bytes):
        offset, count, _r0, _r1 = P.GET_HITS_REQUEST.unpack(payload)
        count = min(count, len(self.hits) - offset) if offset < len(self.hits) else 0
        bases = [m['base'] for m in self.target.mappings]
        header = P.HIT_BATCH_HEADER.pack(self.session_id, count, len(self.hits),
                                         self.value_size, len(bases), 0)
        body = header + b''.join(struct.pack('<Q', b) for b in bases)
        for i in range(offset, offset + count):
            idx, off, value = self.hits[i]
            body += P.HIT.pack(off, idx, getattr(self, 'value_type', P.VT_U32),
                               int.from_bytes(value, 'little'))
        return body
