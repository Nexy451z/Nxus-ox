"""Fail if pc/nxus/protocol.py drifts from core/nxus_protocol.h.

The C header is parsed directly (no build required), so this runs anywhere
Python runs - no hardware, no emulator, no compiler.
"""
import os
import re
import struct
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PC = os.path.dirname(HERE)
ROOT = os.path.dirname(PC)
HEADER_PATH = os.path.join(ROOT, 'core', 'nxus_protocol.h')

# The server-side Result that is not part of the shared wire header: it is
# declared in switch/include/nxus_server.h and mirrored by hand in the two PC
# clients.  All three are read here so a rename/re-number on one side fails
# loudly instead of leaving one client permanently mistaking the pointer-scan
# acknowledgement for an error.
SERVER_HEADER_PATH = os.path.join(ROOT, 'switch', 'include', 'nxus_server.h')
CLIENT_PY_PATH = os.path.join(PC, 'nxus', 'client.py')
CLIENT_RS_PATH = os.path.join(PC, 'Nxus.Cli', 'src', 'client.rs')

sys.path.insert(0, PC)
from nxus import protocol  # noqa: E402
from nxus import mock_switch  # noqa: E402
from nxus.client import NxusClient  # noqa: E402


def read_header():
    with open(HEADER_PATH, 'r', encoding='utf-8') as f:
        return f.read()


def read_text(path):
    with open(path, 'r', encoding='utf-8') as f:
        return f.read()


class ProtocolSemantics(unittest.TestCase):
    """Sizes are not enough: the enum *values* and field offsets must line up too,
    otherwise the console and the PC silently disagree about what a scan means."""

    @classmethod
    def setUpClass(cls):
        cls.text = read_header()

    C_SIZES = {'u8': 1, 'u16': 2, 'u32': 4, 'u64': 8, 's32': 4, 's64': 8,
               'i32': 4, 'i64': 8, 'f32': 4, 'f64': 8}

    def c_struct_fields(self, name):
        """[(field, byte offset)] for a flat packed C struct, or None if the
        struct uses arrays/nested types this simple parser cannot size."""
        close = self.text.index('} ' + name + ';')
        head = self.text.rindex('typedef struct', 0, close)
        body = self.text[self.text.index('{', head) + 1:close]

        out, offset, in_comment = [], 0, False
        for raw in body.splitlines():
            line = ''
            index = 0
            while index < len(raw):
                if in_comment:
                    end = raw.find('*/', index)
                    if end < 0:
                        index = len(raw)
                        break
                    in_comment = False
                    index = end + 2
                    continue
                start = raw.find('/*', index)
                slash = raw.find('//', index)
                if slash >= 0 and (start < 0 or slash < start):
                    line += raw[index:slash]
                    index = len(raw)
                    break
                if start < 0:
                    line += raw[index:]
                    index = len(raw)
                    break
                line += raw[index:start]
                in_comment = True
                index = start + 2

            line = line.strip().rstrip(';').strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) != 2 or parts[0] not in self.C_SIZES:
                return None
            out.append((parts[1], offset))
            offset += self.C_SIZES[parts[0]]
        return out

    @staticmethod
    def py_offsets(fmt):
        """Field offsets of a little-endian packed struct format string."""
        offsets, offset = [], 0
        for code in fmt[1:]:
            offsets.append(offset)
            offset += struct.calcsize(code)
        return offsets

    def assert_offsets(self, c_name, fmt, names=None):
        """Names are compared as well as offsets: two same-width fields swapped in
        either file keep every size and offset intact, so only the order of the
        names reveals it."""
        fields = self.c_struct_fields(c_name)
        self.assertIsNotNone(fields, f'{c_name} is not a flat struct this can size')
        py = self.py_offsets(fmt)
        self.assertEqual(len(fields), len(py), f'{c_name}: field count differs')
        for (name, c_off), p_off in zip(fields, py):
            self.assertEqual(c_off, p_off,
                             f'{c_name}.{name} is at {c_off} in C but {p_off} in Python')
        if names is not None:
            self.assertEqual([n for n, _ in fields], names,
                             f'{c_name}: field order in the C header changed')

    def c_enum(self, name):
        """Extract 'Name = value' pairs from a C enum body."""
        # find this enum's closing brace first, then walk back to its opening
        # brace: the header holds many typedef enums and a lazy match would span
        # several of them.
        close = re.search(r'\}\s*' + name + r'\s*;', self.text)
        self.assertIsNotNone(close, f'enum {name} not found in the header')
        head = self.text.rfind('typedef enum', 0, close.start())
        self.assertGreaterEqual(head, 0, f'enum {name} has no typedef')
        body = self.text[self.text.index('{', head) + 1:close.start()]

        out = {}
        value = 0
        for line in body.splitlines():
            line = line.split('/*')[0].strip().rstrip(',')
            if not line or line.startswith('//'):
                continue
            if '=' in line:
                key, raw = [part.strip() for part in line.split('=', 1)]
                value = int(raw, 0)
            else:
                key = line
            out[key] = value
            value += 1
        return out

    def test_compare_modes_match(self):
        enum = self.c_enum('NxusCompareMode')
        pairs = {
            'NxusCmp_Equal': protocol.CMP_EQUAL,
            'NxusCmp_NotEqual': protocol.CMP_NOT_EQUAL,
            'NxusCmp_Greater': protocol.CMP_GREATER,
            'NxusCmp_Less': protocol.CMP_LESS,
            'NxusCmp_Increased': protocol.CMP_INCREASED,
            'NxusCmp_Decreased': protocol.CMP_DECREASED,
            'NxusCmp_Unchanged': protocol.CMP_UNCHANGED,
            'NxusCmp_Changed': protocol.CMP_CHANGED,
            'NxusCmp_FuzzyEqual': protocol.CMP_FUZZY,
            'NxusCmp_Between': protocol.CMP_BETWEEN,
            'NxusCmp_Unknown': protocol.CMP_UNKNOWN,
            'NxusCmp_GreaterOrEqual': protocol.CMP_GREATER_OR_EQUAL,
            'NxusCmp_LessOrEqual': protocol.CMP_LESS_OR_EQUAL,
            'NxusCmp_Different': protocol.CMP_DIFFERENT,
        }
        for name, expected in pairs.items():
            self.assertIn(name, enum, f'{name} missing from the header')
            self.assertEqual(enum[name], expected, f'{name} drifted')

    def test_value_types_match(self):
        enum = self.c_enum('NxusValueType')
        pairs = {
            'NxusValueType_U8': protocol.VT_U8,
            'NxusValueType_U16': protocol.VT_U16,
            'NxusValueType_U32': protocol.VT_U32,
            'NxusValueType_U64': protocol.VT_U64,
            'NxusValueType_F32': protocol.VT_F32,
            'NxusValueType_F64': protocol.VT_F64,
            'NxusValueType_String': protocol.VT_STRING,
            'NxusValueType_Bytes': protocol.VT_BYTES,
            'NxusValueType_Binary': protocol.VT_BINARY,
            'NxusValueType_All': protocol.VT_ALL,
        }
        for name, expected in pairs.items():
            self.assertIn(name, enum, f'{name} missing from the header')
            self.assertEqual(enum[name], expected, f'{name} drifted')

    def test_scan_flags_match(self):
        defines = dict(re.findall(r'#define\s+(NXUS_SCAN_F_\w+)\s+(0x[0-9A-Fa-f]+)u', self.text))
        pairs = {
            'NXUS_SCAN_F_FLOAT': protocol.SCAN_F_FLOAT,
            'NXUS_SCAN_F_SIGNED': protocol.SCAN_F_SIGNED,
            'NXUS_SCAN_F_HEX': protocol.SCAN_F_HEX,
            'NXUS_SCAN_F_CASE_INSENS': protocol.SCAN_F_CASE_INSENS,
            'NXUS_SCAN_F_UTF16': protocol.SCAN_F_UTF16,
            'NXUS_SCAN_F_WILDCARD': protocol.SCAN_F_WILDCARD,
            'NXUS_SCAN_F_ALIGNED': protocol.SCAN_F_ALIGNED,
        }
        for name, expected in pairs.items():
            self.assertIn(name, defines, f'{name} missing from the header')
            self.assertEqual(int(defines[name], 16), expected, f'{name} drifted')

    def test_status_field_offsets(self):
        # swapping two same-width fields (e.g. process_id/program_id) keeps the
        # size and every value check, but makes every reply decode garbage
        self.assert_offsets('NxusStatus', '<IIIIQQQQIIiIIII', [
            'proto_version', 'mode', 'status_flags', 'scan_state',
            'process_id', 'program_id', 'main_base', 'main_size',
            'hit_count', 'progress_permille', 'last_result', 'uptime_ms',
            'heap_used', 'heap_total', 'max_read'])

    def test_hit_field_offsets(self):
        self.assert_offsets('NxusHit', '<IHHQ', ['offset', 'mapping_idx', 'value_type', 'value'])

    def test_scan_request_field_offsets(self):
        self.assert_offsets('NxusScanRequest', '<IIIIQQQQII', [
            'kind', 'value_size', 'cmp_mode', 'scope',
            'range_begin', 'range_end', 'target', 'target2',
            'chunk_size', 'flags'])

    def test_scan_ext_layout(self):
        # u32 value_type, u32 pattern_len, u32 epsilon_decimals, u32 reserved
        self.assertEqual(protocol.SCAN_EXT.size, 16)
        packed = protocol.SCAN_EXT.pack(protocol.VT_F32, 4, 2, 0)
        self.assertEqual(struct.unpack('<IIII', packed), (4, 4, 2, 0))

    def test_hit_pack_roundtrip(self):
        # the value_type field sits where the engine stores it (NxusHitAddress.reserved)
        self.assertEqual(protocol.HIT.size, 16)
        packed = protocol.HIT.pack(0x11223344, 2, protocol.VT_F32, 0xAABBCCDD)
        self.assertEqual(packed[0:4], (0x11223344).to_bytes(4, 'little'))
        self.assertEqual(packed[4:6], (2).to_bytes(2, 'little'))
        self.assertEqual(packed[6:8], protocol.VT_F32.to_bytes(2, 'little'))
        self.assertEqual(packed[8:16], (0xAABBCCDD).to_bytes(8, 'little'))


class ProtocolParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = read_header()
        cls.defines = {m.group(1): int(m.group(2), 0)
                       for m in re.finditer(r'#define\s+(NXUS_[A-Z0-9_]+)\s+(0x[0-9A-Fa-f]+|\d+)u?', cls.text)}
        cls.enum_members = {}
        for m in re.finditer(r'^\s*(Nxus[A-Za-z0-9_]+)\s*=\s*(0x[0-9A-Fa-f]+|\d+),', cls.text, re.M):
            cls.enum_members[m.group(1)] = int(m.group(2), 0)
        # command ids are declared with the prefix NxusCmd_
        cls.commands = {k[len('NxusCmd_'):]: v for k, v in cls.enum_members.items() if k.startswith('NxusCmd_')}
        cls.events = {k[len('NxusEvent_'):]: v for k, v in cls.enum_members.items() if k.startswith('NxusEvent_')}
        cls.asserts = {m.group(1): int(m.group(2), 0)
                       for m in re.finditer(r'NXUS_STATIC_ASSERT\(sizeof\((\w+)\)\s*==\s*(0x[0-9A-Fa-f]+|\d+)', cls.text)}

    def test_magic_and_port(self):
        self.assertEqual(protocol.MAGIC, self.defines['NXUS_MAGIC'])
        self.assertEqual(protocol.DEFAULT_PORT, self.defines['NXUS_DEFAULT_PORT'])
        self.assertEqual(protocol.PROTO_VERSION, self.defines['NXUS_PROTO_VERSION'])

    def test_flags(self):
        for name in ('NXUS_FLAG_ASYNC', 'NXUS_FLAG_ERROR', 'NXUS_FLAG_MORE'):
            self.assertEqual(getattr(protocol, name.split('_', 1)[1]), self.defines[name], name)

    def test_status_flags(self):
        for name, value in protocol.ST.items():
            self.assertEqual(value, self.defines[name], name)

    def test_scan_flags(self):
        for name, value in protocol.SCAN_F.items():
            self.assertEqual(value, self.defines[name], name)

    def test_perm_flags(self):
        for name, value in protocol.PERM.items():
            self.assertEqual(value, self.defines[name], name)

    def test_commands(self):
        self.assertEqual(set(protocol.CMD), set(self.commands),
                         f"command name mismatch: only-C {set(self.commands) - set(protocol.CMD)}, "
                         f"only-python {set(protocol.CMD) - set(self.commands)}")
        for name, value in protocol.CMD.items():
            self.assertEqual(value, self.commands[name], name)

    def test_events(self):
        self.assertEqual(set(protocol.EVT), set(self.events))
        for name, value in protocol.EVT.items():
            self.assertEqual(value, self.events[name], name)

    def test_enum_tables(self):
        for table, prefix in ((protocol.CMP, 'NxusCmp_'),
                              (protocol.SCOPE, 'NxusScope_'),
                              (protocol.SCAN_STATE, 'NxusScanState_'),
                              (protocol.SCAN_KIND, 'NxusScanKind_'),
                              (protocol.BREAK_KIND, 'NxusBp_'),
                              (protocol.PROBE, 'NxusProbe_')):
            for name, value in table.items():
                self.assertIn(name, self.enum_members, f"{name} missing from the C header")
                self.assertEqual(value, self.enum_members[name], name)

    def test_mode_constants(self):
        for name, value in protocol.MODE.items():
            self.assertEqual(value, self.defines[name], name)

    def test_struct_sizes(self):
        self.assertTrue(self.asserts, "no NXUS_STATIC_ASSERT(sizeof(...)) found in the header")
        for c_name, expected in self.asserts.items():
            self.assertIn(c_name, protocol.STRUCTS, f"{c_name} has no Python mirror")
            actual = protocol.STRUCTS[c_name].size
            self.assertEqual(actual, expected, f"{c_name}: python {actual} != C {expected}")

    def test_header_is_16_bytes(self):
        self.assertEqual(protocol.HEADER_SIZE, 16)
        self.assertEqual(len(protocol.pack_header(0x0003)), 16)

    def test_header_roundtrip(self):
        blob = protocol.pack_header(protocol.CMD['Read'], flags=0, length=12, seq=0xDEADBEEF)
        magic, mtype, flags, length, seq = protocol.unpack_header(blob)
        self.assertEqual((magic, mtype, flags, length, seq),
                         (protocol.MAGIC, protocol.CMD['Read'], 0, 12, 0xDEADBEEF))

    def test_hit_batch_layout(self):
        """A hit batch must be parseable: header + mapping bases + hits."""
        header = protocol.HIT_BATCH_HEADER.pack(1, 2, 2, 4, 1, 0)
        bases = struct.pack('<Q', 0x10000000)
        hits = protocol.HIT.pack(0x1000, 0, 0, 0xDEADBEEF) + protocol.HIT.pack(0x2000, 0, 0, 0xCAFEBABE)
        blob = header + bases + hits
        session, count, total, value_size, mapping_count, _res = protocol.HIT_BATCH_HEADER.unpack_from(blob, 0)
        self.assertEqual((session, count, total, value_size, mapping_count), (1, 2, 2, 4, 1))
        off = protocol.HIT_BATCH_HEADER.size + 8 * mapping_count
        got = []
        for _ in range(count):
            o, mi, _r, v = protocol.HIT.unpack_from(blob, off)
            got.append((o, mi, v))
            off += protocol.HIT.size
        self.assertEqual(got, [(0x1000, 0, 0xDEADBEEF), (0x2000, 0, 0xCAFEBABE)])


class AsyncPtrScanResultParity(unittest.TestCase):
    """NXUS_RESULT_PTRSCAN_STARTED has to mean the same thing everywhere.

    PtrScanBegin no longer answers with the chain list: it acknowledges with
    ``NXUS_RESULT_PTRSCAN_STARTED`` (``NXUS_MAKE_RESULT(NXUS_ERR_PTRSCAN_STARTED)``,
    desc 8) and the client polls PtrScanGet, which answers ``NXUS_ERR_BUSY`` until
    the walk publishes its result.

    The value lives in switch/include/nxus_server.h - a *server* status, not part
    of the shared wire format in core/nxus_protocol.h - so the Rust CLI
    (``RESULT_PTRSCAN_STARTED``) and the Python client (``PTRSCAN_STARTED``) each
    mirror it by hand.  If one of them drifts, that client either prints the
    acknowledgement as a failure and drops every chain, or fails to recognise the
    BUSY reply and reports an empty chain list.  Both are silent data loss, so
    the three definitions are read from the sources and compared against the
    encoding the protocol module implements.
    """

    # NXUS_MAKE_RESULT(8) with the Nxus result module (484 = 0x1E4):
    # 0x8003C808.  Spelled out here so the test fails if the encoding itself
    # changes under all three call sites at once.
    RESULT = 0x8003C808
    DESC = 8

    def test_the_value_is_the_shared_result_encoding(self):
        self.assertEqual(self.RESULT, protocol.make_result(self.DESC))
        self.assertEqual(self.RESULT, 0x80000000 | (protocol.RESULT_MODULE << 9) | self.DESC)
        self.assertEqual(protocol.RESULT_MODULE, 484)

    def test_c_header_defines_the_descriptor_and_wraps_it(self):
        text = read_text(SERVER_HEADER_PATH)
        match = re.search(r'#define\s+NXUS_ERR_PTRSCAN_STARTED\s+(\d+)u?\b', text)
        self.assertIsNotNone(match, 'NXUS_ERR_PTRSCAN_STARTED missing from nxus_server.h')
        desc = int(match.group(1), 0)
        self.assertEqual(desc, self.DESC,
                         f'nxus_server.h: descriptor {desc} != {self.DESC}')
        # the header must build the Result from the descriptor, not hard-code a word
        self.assertIn('NXUS_MAKE_RESULT(NXUS_ERR_PTRSCAN_STARTED)', text,
                      'nxus_server.h no longer encodes the Result from its descriptor')
        self.assertEqual(protocol.make_result(desc), self.RESULT)

    def test_rust_cli_constant(self):
        text = read_text(CLIENT_RS_PATH)
        match = re.search(r'pub\s+const\s+RESULT_PTRSCAN_STARTED\s*:\s*u32\s*=\s*'
                          r'(0x[0-9A-Fa-f_]+|\d+)\s*;', text)
        self.assertIsNotNone(match, 'RESULT_PTRSCAN_STARTED missing from Nxus.Cli/src/client.rs')
        value = int(match.group(1).replace('_', ''), 0)
        self.assertEqual(value, self.RESULT,
                         f'Rust RESULT_PTRSCAN_STARTED is {value:#010X}, C says {self.RESULT:#010X}')
        self.assertEqual(value, protocol.make_result(self.DESC))

    def test_python_client_constant(self):
        self.assertEqual(NxusClient.PTRSCAN_STARTED, self.RESULT,
                         'Python PTRSCAN_STARTED drifted from the C header')
        self.assertEqual(NxusClient.PTRSCAN_STARTED, protocol.make_result(self.DESC))
        # the mock speaks the same acknowledgement on the wire
        self.assertEqual(mock_switch.PTRSCAN_STARTED, self.RESULT,
                         'the mock acknowledges with a different Result')

    def test_busy_result_matches_too(self):
        """The other half of the poll contract: BUSY is what "keep polling" means."""
        text = read_text(CLIENT_RS_PATH)
        match = re.search(r'pub\s+const\s+RESULT_BUSY\s*:\s*u32\s*=\s*'
                          r'(0x[0-9A-Fa-f_]+|\d+)\s*;', text)
        self.assertIsNotNone(match, 'RESULT_BUSY missing from Nxus.Cli/src/client.rs')
        value = int(match.group(1).replace('_', ''), 0)
        self.assertEqual(value, protocol.make_result(protocol.ERR_BUSY),
                         'Rust RESULT_BUSY drifted from the Python protocol module')


if __name__ == '__main__':
    unittest.main(verbosity=2)
