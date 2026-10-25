"""Nxus PC-side client: seq-correlated requests + an asynchronous event queue.

Works against the real sysmodule and against pc/nxus/mock_switch.py, so the
whole protocol can be exercised without a console.
"""
from __future__ import annotations

import queue
import socket
import threading
import time

from . import protocol as P


class NxusError(RuntimeError):
    """Raised when the Switch returns an error Result."""

    def __init__(self, cmd: int, result: int):
        self.cmd = cmd
        self.result = result & 0xFFFFFFFF
        name = next((k for k, v in P.CMD.items() if v == cmd), hex(cmd))
        super().__init__(f"{name} failed: result=0x{self.result:08X}")


class NxusDisconnected(RuntimeError):
    pass


class NxusClient:
    def __init__(self, host: str = '127.0.0.1', port: int = P.DEFAULT_PORT, timeout: float = 3.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.max_read = 0                   # filled in from the status reply
        self._sock: socket.socket | None = None
        self._rx_thread: threading.Thread | None = None
        self._running = False
        self._seq = 0
        self._seq_lock = threading.Lock()
        self._pending: dict[int, queue.Queue] = {}
        self._pending_lock = threading.Lock()
        self.events: queue.Queue = queue.Queue()
        self.last_error: int | None = None
        # FROZEN_LIST bookkeeping: the addresses the previous reply reported, and
        # the ones the console dropped since then (see frozen_list_diff()).
        self._last_frozen: list[int] = []
        self._released_frozen: list[int] = []

    # ---- lifecycle ----

    def connect(self, timeout: float | None = None) -> 'NxusClient':
        self._sock = socket.create_connection((self.host, self.port), timeout=timeout or self.timeout)
        self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self._sock.settimeout(0.2)
        self._running = True
        self._rx_thread = threading.Thread(target=self._recv_loop, name='nxus-rx', daemon=True)
        self._rx_thread.start()
        return self

    def close(self) -> None:
        self._running = False
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        if self._rx_thread is not None:
            self._rx_thread.join(timeout=1.0)
            self._rx_thread = None

    def __enter__(self):
        return self.connect()

    def __exit__(self, *exc):
        self.close()

    # ---- transport ----

    def _recv_exact(self, count: int) -> bytes:
        chunks = []
        got = 0
        while got < count:
            try:
                chunk = self._sock.recv(count - got)
            except socket.timeout:
                if not self._running:
                    raise NxusDisconnected('closed')
                continue
            if not chunk:
                raise NxusDisconnected('peer closed the connection')
            chunks.append(chunk)
            got += len(chunk)
        return b''.join(chunks)

    def _recv_loop(self) -> None:
        try:
            while self._running:
                head = self._recv_exact(P.HEADER_SIZE)
                magic, mtype, flags, length, seq = P.HEADER.unpack(head)
                if magic != P.MAGIC:
                    raise NxusDisconnected(f'bad magic 0x{magic:08X}')
                payload = self._recv_exact(length) if length else b''
                if P.is_event(mtype, flags):
                    self.events.put({'type': mtype, 'flags': flags, 'payload': payload, 'time': time.time()})
                else:
                    with self._pending_lock:
                        waiter = self._pending.pop(seq, None)
                    if waiter is not None:
                        waiter.put((mtype, flags, payload))
        except (NxusDisconnected, OSError):
            pass
        finally:
            with self._pending_lock:
                for waiter in self._pending.values():
                    waiter.put(None)
                self._pending.clear()

    def request(self, cmd: int, payload: bytes = b'', timeout: float | None = None):
        """Send a command and wait for its response. Returns (type, flags, payload)."""
        with self._seq_lock:
            self._seq = (self._seq + 1) & 0xFFFFFFFF
            seq = self._seq
        waiter: queue.Queue = queue.Queue(maxsize=1)
        with self._pending_lock:
            self._pending[seq] = waiter
        if self._sock is None:
            raise NxusDisconnected('not connected')
        self._sock.sendall(P.pack_header(cmd, 0, len(payload), seq) + payload)
        try:
            item = waiter.get(timeout=timeout or self.timeout)
        except queue.Empty:
            raise TimeoutError(f'no reply for cmd 0x{cmd:04X} seq={seq}')
        if item is None:
            raise NxusDisconnected('connection closed while waiting for a reply')
        mtype, flags, body = item
        if flags & P.FLAG_ERROR:
            self.last_error = int.from_bytes(body[:4], 'little', signed=False)
            raise NxusError(cmd, self.last_error)
        return mtype, flags, body

    def poll_event(self, timeout: float = 0.0):
        try:
            return self.events.get(timeout=timeout) if timeout > 0 else self.events.get_nowait()
        except queue.Empty:
            return None

    # ---- commands ----

    def nop(self):
        self.request(P.CMD['Nop'])

    def heartbeat(self):
        self.request(P.CMD['Heartbeat'])

    def pause(self):
        self.request(P.CMD['Pause'])

    def resume(self):
        self.request(P.CMD['Resume'])

    def get_status(self) -> dict:
        _, _, body = self.request(P.CMD['GetStatus'])
        (proto, mode, flags, scan_state, pid, title, main_base, main_size,
         hits, progress, last_result, uptime, heap_used, heap_total, max_read) = P.STATUS.unpack(body)
        if max_read:
            self.max_read = max_read        # read() uses this to split big requests
        return dict(proto=proto, mode=mode, flags=flags, scan_state=scan_state, pid=pid,
                    title=title, main_base=main_base, main_size=main_size, hits=hits,
                    progress=progress, last_result=last_result, uptime=uptime,
                    heap_used=heap_used, heap_total=heap_total, max_read=max_read,
                    paused=bool(flags & P.ST['NXUS_ST_PAUSED']),
                    scanning=bool(flags & P.ST['NXUS_ST_SCANNING']))

    def get_metadata(self) -> dict:
        _, _, body = self.request(P.CMD['GetMetadata'])
        values = P.PROCESS_METADATA.unpack(body)
        keys = ['pid', 'title', 'main_base', 'main_size', 'heap_base', 'heap_size',
                'alias_base', 'alias_size', 'aslr_base', 'aslr_size', 'build_id']
        out = dict(zip(keys, values))
        out['build_id'] = out['build_id'].hex()
        return out

    def get_mapping_count(self) -> int:
        _, _, body = self.request(P.CMD['GetMappingCount'])
        return int.from_bytes(body[:8], 'little')

    def get_mappings(self, offset: int = 0, count: int = 64) -> list[dict]:
        _, _, body = self.request(P.CMD['GetMappings'], P.MAPPINGS_REQUEST.pack(offset, count, 0))
        out = []
        for i in range(len(body) // P.MEMORY_INFO.size):
            (base, size, mtype, attr, perm, dev, ipc, _pad) = P.MEMORY_INFO.unpack_from(body, i * P.MEMORY_INFO.size)
            out.append(dict(base=base, size=size, type=mtype, attr=attr, perm=perm))
        return out

    def query(self, address: int) -> dict:
        _, _, body = self.request(P.CMD['Query'], address.to_bytes(8, 'little'))
        base, size, mtype, attr, perm, dev, ipc, _pad = P.MEMORY_INFO.unpack(body)
        return dict(base=base, size=size, type=mtype, attr=attr, perm=perm)

    def read(self, address: int, size: int) -> bytes:
        """Read memory, splitting the request when the console caps it.

        The server advertises the largest single read it accepts in the status
        reply; asking for more is rejected outright, so chunk to be safe.
        """
        cap = getattr(self, 'max_read', 0) or 64 * 1024
        want_cap = cap
        out = bytearray()
        offset = 0
        while len(out) < size:
            want = min(want_cap, size - len(out))
            _, _, body = self.request(P.CMD['Read'], P.READ_REQUEST.pack(address + offset, want, 0))
            if not body:
                break
            out += body
            offset += len(body)
            if len(body) < want:
                # The console halves a read dmnt refuses, so a short reply means
                # "not that much at once": ask for the rest in smaller pieces
                # instead of handing back partial data.
                smaller = max(len(body), 4096)
                if smaller >= want:
                    break
                want_cap = smaller
        return bytes(out)

    def write(self, address: int, data: bytes) -> None:
        self.request(P.CMD['Write'], P.WRITE_HEADER.pack(address, len(data), 0) + data)

    def get_modules(self) -> list[dict]:
        _, _, body = self.request(P.CMD['GetModules'])
        out = []
        for i in range(len(body) // P.MODULE_INFO.size):
            base, size, build_id, name = P.MODULE_INFO.unpack_from(body, i * P.MODULE_INFO.size)
            out.append(dict(base=base, size=size, build_id=build_id.hex(),
                            name=name.split(b'\0')[0].decode('ascii', 'replace')))
        return out

    # ---- scanning ----

    def scan_begin(self, value, value_size: int = 4, cmp_mode: int = 0, scope: int = 0,
                   target2: int = 0, flags: int = 0, range_begin: int = 0, range_end: int = 0,
                   chunk_size: int = 0) -> dict:
        payload = P.SCAN_REQUEST.pack(0, value_size, cmp_mode, scope, range_begin, range_end,
                                      value & 0xFFFFFFFFFFFFFFFF, target2, chunk_size, flags)
        _, _, body = self.request(P.CMD['ScanBegin'], payload)
        return self._status_from(body)

    def scan_next(self, value: int = 0, cmp_mode: int = 0, target2: int = 0, flags: int = 0) -> dict:
        payload = P.SCAN_REQUEST.pack(1, 0, cmp_mode, 0, 0, 0, value & 0xFFFFFFFFFFFFFFFF, target2, 0, flags)
        _, _, body = self.request(P.CMD['ScanNext'], payload)
        return self._status_from(body)

    def scan_status(self) -> dict:
        _, _, body = self.request(P.CMD['ScanStatus'])
        return self._status_from(body)

    def scan_cancel(self):
        self.request(P.CMD['ScanCancel'])

    def scan_reset(self):
        self.request(P.CMD['ScanReset'])

    # ---- pointer scan / cheat export ----

    def ptr_scan_begin(self, target_address: int, module_base: int = 0, max_depth: int = 3,
                       max_offset: int = 0x1000, max_results: int = 64,
                       value_width: int = 4) -> list[dict]:
        payload = P.PTRSCAN_REQUEST.pack(target_address, module_base, max_depth, max_offset,
                                         max_results, value_width)
        _, _, body = self.request(P.CMD['PtrScanBegin'], payload, timeout=30.0)
        return self._parse_chains(body)

    def ptr_scan_get(self) -> list[dict]:
        _, _, body = self.request(P.CMD['PtrScanGet'])
        return self._parse_chains(body)

    def cheat_export(self, index: int, value: int, value_width: int = 4, is_32bit: bool = True) -> str:
        flags = P.CHEAT_F_32BIT if is_32bit else 0
        payload = P.CHEAT_EXPORT_REQUEST.pack(index, value_width, flags, 0, value)
        _, _, body = self.request(P.CMD['CheatExport'], payload)
        return body.decode('utf-8')

    def _parse_chains(self, body: bytes) -> list[dict]:
        count, total, truncated, _res = P.PTR_CHAIN_LIST_HEADER.unpack_from(body, 0)
        pos = P.PTR_CHAIN_LIST_HEADER.size
        out = []
        for _ in range(count):
            root, final, step_count, _r, *steps = P.PTR_CHAIN.unpack_from(body, pos)
            pos += P.PTR_CHAIN.size
            out.append(dict(root_offset=root, final_offset=final,
                            step_count=step_count, steps=steps[:step_count]))
        # The console sets this when it stopped on max_results or on the read
        # budget: the chains below are valid but the list is not exhaustive.
        self.last_chains_truncated = bool(truncated)
        if truncated:
            print(f"warning: pointer scan stopped early - {count} of {total} chains "
                  f"returned, more may exist")
        return out

    def scan_wait(self, timeout: float = 10.0, poll: float = 0.02) -> dict:
        deadline = time.time() + timeout
        state = self.scan_status()
        while time.time() < deadline:
            if state['scan_state'] in (P.SCAN_STATE['NxusScanState_Done'],
                                       P.SCAN_STATE['NxusScanState_Error'],
                                       P.SCAN_STATE['NxusScanState_Cancelled']):
                return state
            time.sleep(poll)
            state = self.scan_status()
        raise TimeoutError('scan did not finish')

    def scan_hits(self, offset: int = 0, count: int = 4096) -> dict:
        _, _, body = self.request(P.CMD['ScanGetHits'], P.GET_HITS_REQUEST.pack(offset, count, 0, 0))
        session, n, total, value_size, mapping_count, flags = P.HIT_BATCH_HEADER.unpack_from(body, 0)
        pos = P.HIT_BATCH_HEADER.size
        bases = []
        for _ in range(mapping_count):
            bases.append(int.from_bytes(body[pos:pos + 8], 'little'))
            pos += 8
        hits = []
        for _ in range(n):
            off, map_idx, _r, value = P.HIT.unpack_from(body, pos)
            pos += P.HIT.size
            base = bases[map_idx] if map_idx < len(bases) else 0
            hits.append(dict(address=base + off, offset=off, mapping_idx=map_idx, value=value))
        return dict(session=session, count=n, total=total, value_size=value_size,
                    bases=bases, hits=hits,
                    truncated=bool(flags & P.HITBATCH_TRUNCATED))

    def scan_all_hits(self, page: int = 4096) -> list[dict]:
        self.last_scan_truncated = False
        out = []
        truncated = False
        while True:
            batch = self.scan_hits(len(out), page)
            truncated = truncated or batch.get('truncated', False)
            out.extend(batch['hits'])
            if len(out) >= batch['total'] or not batch['hits']:
                # The console reports "hit list full" through the batch flags; keep
                # it so callers (and users) can tell a complete list from a cut-off
                # one instead of treating both as final.
                self.last_scan_truncated = truncated
                if truncated:
                    print(f"warning: the console hit its hit-list limit - "
                          f"{len(out)} hits collected, more may exist")
                return out

    @staticmethod
    def _status_from(body: bytes) -> dict:
        (proto, mode, flags, scan_state, pid, title, main_base, main_size,
         hits, progress, last_result, uptime, heap_used, heap_total, _res) = P.STATUS.unpack(body)
        return dict(proto=proto, mode=mode, flags=flags, scan_state=scan_state, pid=pid,
                    title=title, main_base=main_base, main_size=main_size, hits=hits,
                    progress=progress, last_result=last_result, uptime=uptime)

    # ---- freeze / config ----

    def frozen_list(self) -> list[dict]:
        """Current frozen entries (`FrozenList`).

        The console answers with a bare `NxusFrozenEntry[]` and the count is
        implied by the payload length, so an empty payload is a valid "nothing is
        frozen".  Every reply becomes the baseline for frozen_list_diff().
        """
        _, _, body = self.request(P.CMD['FrozenList'])
        entries = []
        for i in range(len(body) // P.FROZEN_ENTRY.size):
            address, value, width, _res = P.FROZEN_ENTRY.unpack_from(body, i * P.FROZEN_ENTRY.size)
            entries.append(dict(address=address, value=value, width=width))
        self._record_frozen([entry['address'] for entry in entries])
        return entries

    def frozen_list_diff(self) -> list[int]:
        """Addresses that were frozen at the previous frozen_list() and are gone.

        The console releases every address Nxus itself froze once the last client
        has been gone for ~30 s (`releaseOwnedFrozen()` in
        switch/source/nxus_server.c) and only writes that to its own log ring / SD
        file, never on the wire.  This difference is therefore the only material
        the PC has; an address that appeared is a new freeze, not a release.
        """
        return list(self._released_frozen)

    def last_frozen(self) -> list[int]:
        """Addresses the last frozen_list() reported (empty before the first)."""
        return list(self._last_frozen)

    def _record_frozen(self, addresses: list[int]) -> None:
        current = list(addresses)
        self._released_frozen = sorted({a for a in self._last_frozen if a not in current})
        self._last_frozen = current

    def _note_frozen_enabled(self, address: int) -> None:
        """Remember a freeze this client made: it is neither a release nor a
        missing baseline entry."""
        self._released_frozen = [a for a in self._released_frozen if a != address]
        if address not in self._last_frozen:
            self._last_frozen.append(address)

    def _note_frozen_disabled(self, address: int) -> None:
        """A freeze this client removed on purpose must not look like the console
        releasing it."""
        self._released_frozen = [a for a in self._released_frozen if a != address]
        self._last_frozen = [a for a in self._last_frozen if a != address]

    def frozen_enable(self, address: int, width: int) -> int:
        _, _, body = self.request(P.CMD['FrozenEnable'], P.FROZEN_REQUEST.pack(address, width, 0))
        self._note_frozen_enabled(address)
        return int.from_bytes(body[:8], 'little')

    def frozen_disable(self, address: int):
        self.request(P.CMD['FrozenDisable'], address.to_bytes(8, 'little'))
        self._note_frozen_disabled(address)

    # ---- debug mode ----

    def processes(self) -> list[int]:
        _, _, body = self.request(P.CMD['GetProcesses'])
        return [int.from_bytes(body[i:i + 8], 'little') for i in range(0, len(body) // 8 * 8, 8)]

    def debug_attach(self, pid: int = 0) -> dict:
        payload = pid.to_bytes(8, 'little') if pid else b''
        _, _, body = self.request(P.CMD['DebugAttach'], payload, timeout=20.0)
        return self._debug_status_from(body)

    def debug_detach(self):
        self.request(P.CMD['DebugDetach'], timeout=20.0)

    def debug_status(self) -> dict:
        _, _, body = self.request(P.CMD['DebugStatus'])
        return self._debug_status_from(body)

    @staticmethod
    def _debug_status_from(body: bytes) -> dict:
        (attached, style, breaks, hits, threads, last_result, auto_continue,
         stopped_thread_low) = P.DEBUG_STATUS.unpack(body)
        return dict(attached=bool(attached), watch_style=style, break_count=breaks,
                    hit_count=hits, thread_count=threads, last_result=last_result,
                    auto_continue=auto_continue,
                    stopped_thread=stopped_thread_low or None,
                    stopped_thread_low=stopped_thread_low)

    def break_set(self, address: int, kind: int, size: int = 4, slot: int = 0,
                  ctrl: int = 0) -> list[dict]:
        payload = P.BREAK_REQUEST.pack(slot, kind, size, ctrl, address)
        _, _, body = self.request(P.CMD['BreakSet'], payload, timeout=20.0)
        return self._parse_breaks(body)

    def break_clear(self, slot: int):
        self.request(P.CMD['BreakClear'], slot.to_bytes(4, 'little'))

    def break_list(self) -> list[dict]:
        _, _, body = self.request(P.CMD['BreakList'])
        return self._parse_breaks(body)

    @staticmethod
    def _parse_breaks(body: bytes) -> list[dict]:
        out = []
        for i in range(len(body) // P.BREAK_ENTRY.size):
            slot, kind, size, enabled, address, ctrl = P.BREAK_ENTRY.unpack_from(body, i * P.BREAK_ENTRY.size)
            out.append(dict(slot=slot, kind=kind, size=size, enabled=bool(enabled),
                            address=address, ctrl=ctrl))
        return out

    def debug_continue(self):
        self.request(P.CMD['DebugContinue'])

    def debug_step(self, thread_id: int = 0):
        """Single-step the held thread (0 = whichever thread the console holds)."""
        self.request(P.CMD['DebugStep'],
                     (thread_id & 0xFFFFFFFFFFFFFFFF).to_bytes(8, 'little'), timeout=20.0)

    def debug_stopped_thread(self):
        """Thread the console is holding at a breakpoint (None = running)."""
        return self.debug_status()['stopped_thread']

    def thread_list(self) -> list[dict]:
        _, _, body = self.request(P.CMD['ThreadList'])
        out = []
        for i in range(len(body) // P.THREAD_ENTRY.size):
            tid, state, prio, core, _r = P.THREAD_ENTRY.unpack_from(body, i * P.THREAD_ENTRY.size)
            out.append(dict(thread_id=tid, state=state, priority=prio, core=core))
        return out

    def regs_get(self, thread_id: int) -> dict:
        _, _, body = self.request(P.CMD['RegsGet'], thread_id.to_bytes(8, 'little'))
        values = P.THREAD_CONTEXT.unpack(body)
        return dict(thread_id=values[0], pc=values[1], lr=values[2], sp=values[3], fp=values[4],
                    cpsr=values[5], r=list(values[6:19]), x=list(values[20:49]),
                    _orig_r=list(values[6:19]))

    def regs_set(self, ctx: dict):
        thread_id = ctx['thread_id']
        r_in = (list(ctx.get('r', [])) + [0] * 13)[:13]
        x_in = (list(ctx.get('x', [])) + [0] * 29)[:29]
        orig_r = ctx.get('_orig_r')
        for i in range(13):
            if orig_r is not None and r_in[i] != orig_r[i] and (x_in[i] & 0xFFFFFFFF) == orig_r[i]:
                x_in[i] = (x_in[i] & ~0xFFFFFFFF) | (r_in[i] & 0xFFFFFFFF)
            elif x_in[i] == 0 and r_in[i] != 0 and 'x' not in ctx:
                x_in[i] = r_in[i] & 0xFFFFFFFF
            r_in[i] = x_in[i] & 0xFFFFFFFF
        payload = P.THREAD_CONTEXT.pack(thread_id, ctx['pc'], ctx['lr'], ctx['sp'], ctx['fp'],
                                        ctx['cpsr'], *r_in, 1, *x_in)
        self.request(P.CMD['RegsSet'], payload)

    def hit_get(self, count: int = 32) -> list[dict]:
        _, _, body = self.request(P.CMD['HitGet'], P.GET_HITS_REQUEST.pack(0, count, 0, 0))
        out = []
        for i in range(len(body) // P.BREAK_HIT.size):
            v = P.BREAK_HIT.unpack_from(body, i * P.BREAK_HIT.size)
            out.append(dict(index=v[0], kind=v[1], slot=v[2], thread_id_low=v[3], address=v[4],
                            pc=v[5], lr=v[6], sp=v[7], cpsr=v[8], r=list(v[9:22]), tick=v[22]))
        return out

    def hit_clear(self):
        self.request(P.CMD['HitClear'])

    def set_debug_config(self, style: int = P.WATCH_STYLE_LINK5, auto_continue: int = 1) -> dict:
        payload = P.CONFIG.pack(0, 0, 0, 0, 0, 0, 0) + P.DEBUG_CONFIG.pack(style, auto_continue, 0, 0)
        _, _, body = self.request(P.CMD['Config'], payload)
        return dict(zip(['hotkey_mask', 'hotkey_hold_ms', 'hotkey_enabled', 'chunk_size',
                         'watchdog_timeout_ms', 'heartbeat_interval_ms', 'log_level'],
                        P.CONFIG.unpack(body)))

    def get_log(self) -> str:
        _, _, body = self.request(P.CMD['LogGet'])
        return body.decode('utf-8', 'replace')

    def set_config(self, watchdog_timeout_ms: int = 0, chunk_size: int = 0) -> dict:
        payload = P.CONFIG.pack(0, 0, 0, chunk_size, watchdog_timeout_ms, 0, 0)
        _, _, body = self.request(P.CMD['Config'], payload)
        return dict(zip(['hotkey_mask', 'hotkey_hold_ms', 'hotkey_enabled', 'chunk_size',
                         'watchdog_timeout_ms', 'heartbeat_interval_ms', 'log_level'],
                        P.CONFIG.unpack(body)))
