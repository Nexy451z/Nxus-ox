/*
 * Host tests for the console-side cheat service (switch/source/nxus_cheat_srv.c).
 *
 * core/nxus_cheatvm.c is already covered by test_cheatvm.c (118 checks: install
 * validation, every opcode family, the journal).  What this test covers is the
 * SERVICE layer above it, which the host could not reach before:
 *
 *   - upload validation: the interpreter's own rejections, a program built for
 *     another title, an upload with no target, and a refused upload that leaves the
 *     running program AND its journal untouched,
 *   - the target stamp: a pid / title / dmnt-incarnation change stops every block,
 *     writes the journalled originals back, drops the journal and publishes exactly
 *     one NxusEvent_CheatFault(NXUS_CHEAT_FAULT_TARGET_GONE); no further tick runs
 *     until a re-upload,
 *   - the 3-tick auto-disable: two failures keep a block alive, the third disables
 *     it and reports the interpreter error, and one success re-arms the window,
 *   - the journal-full path (immediate disable, NXUS_CHEAT_FAULT_JOURNAL_FULL),
 *   - PanicOff: restored/failed/blocks_stopped, a partial failure that keeps the
 *     journal for a retry, and the second call being a no-op,
 *   - CheatClear: the program goes away WITHOUT any write to the target,
 *   - the IO adapter: allow_rx selects the RX-patch range policy (not the plain
 *     writable one), a refused range means no write at all, and one validated
 *     range is reused inside a tick,
 *   - the HID mask is sampled on every tick (key-conditional codes react live),
 *   - the lifecycle: the worker loop stops on the server gate / exit, Init is
 *     idempotent and Exit is safe twice, and the static footprint asserts hold.
 *
 * The SHIPPED service is compiled, not a copy: run_tests.sh puts tests/stubs first
 * (libnx + the session/dmnt/HID/server/net doubles) and this file includes the .c,
 * which is what makes its static worker step reachable.  The stub's threadCreate()
 * fails on purpose, so the worker thread never exists and each tick is driven by the
 * test - the same technique test_snapshot_owner.c uses for its static stamps.
 */
#include <stdio.h>
#include <string.h>

#include "nxus_cheat_srv.h"
#include "nxus_cheat_stub.h"

#include "../switch/source/nxus_cheat_srv.c"

static int g_checks = 0;
static int g_failures = 0;

#define CHECK(cond, ...) do {                                        \
        g_checks++;                                                  \
        if (!(cond)) {                                               \
            g_failures++;                                            \
            printf("  FAIL %s:%d: ", __FILE__, __LINE__);            \
            printf(__VA_ARGS__);                                     \
            puts("");                                                \
        }                                                            \
    } while (0)

/* ---- wire-program builder ----------------------------------------------- */

/*
 * The wire layout nxusCheatInstall() expects: header, then every block, then every
 * instruction.  A block's `first` is fixed when the block is created, so insns are
 * added block by block (which is what the PC's linker produces anyway).
 */
typedef struct {
    NxusCheatProgramHeader header;
    NxusCheatBlockDesc     blocks[8];
    NxusCheatInsn          insns[64];
    u32                    block_count;
    u32                    insn_count;
    u8                     buf[2048];
} Wire;

static void wireStart(Wire *w, u64 program_id) {
    memset(w, 0, sizeof(*w));
    w->header.magic = NXUS_CHEATVM_MAGIC;
    w->header.version = NXUS_CHEATVM_VERSION;
    w->header.build_id = 0x0123456789ABCDEFull;
    w->header.program_id = program_id;
}

static u32 wireBlock(Wire *w, u32 mode, u32 enabled) {
    NxusCheatBlockDesc *b = &w->blocks[w->block_count];
    memset(b, 0, sizeof(*b));
    b->index = w->block_count;
    b->mode = mode;
    b->first = w->insn_count;
    b->count = 0;
    b->enabled = enabled;
    return w->block_count++;
}

static void wireInsn(Wire *w, u32 block, NxusCheatInsn insn) {
    w->insns[w->insn_count] = insn;
    w->blocks[block].count++;
    w->insn_count++;
}

static NxusCheatInsn insnStore(u64 address, u32 width, u64 value) {
    NxusCheatInsn in;
    memset(&in, 0, sizeof(in));
    in.op = (u16)NxusCheatOp_StoreStatic;
    in.width = (u8)width;
    in.region = (u8)NxusCheatRegion_Absolute;
    in.address = (u32)address;
    in.value = value;
    return in;
}

static NxusCheatInsn insnKeypress(u64 mask, u32 target) {
    NxusCheatInsn in;
    memset(&in, 0, sizeof(in));
    in.op = (u16)NxusCheatOp_KeypressConditional;
    in.value = mask;
    in.target = target;
    return in;
}

static NxusCheatInsn insnNop(void) {
    NxusCheatInsn in;
    memset(&in, 0, sizeof(in));
    in.op = (u16)NxusCheatOp_Nop;
    return in;
}

static const void *wireBuild(Wire *w, u32 *out_length) {
    u32 offset = 0;

    w->header.block_count = w->block_count;
    w->header.insn_count = w->insn_count;
    w->header.total_bytes = (u32)(sizeof(NxusCheatProgramHeader) +
                                  w->block_count * sizeof(NxusCheatBlockDesc) +
                                  w->insn_count * sizeof(NxusCheatInsn));
    memcpy(w->buf + offset, &w->header, sizeof(w->header));
    offset += (u32)sizeof(w->header);
    memcpy(w->buf + offset, w->blocks, w->block_count * sizeof(NxusCheatBlockDesc));
    offset += w->block_count * (u32)sizeof(NxusCheatBlockDesc);
    memcpy(w->buf + offset, w->insns, w->insn_count * sizeof(NxusCheatInsn));
    offset += w->insn_count * (u32)sizeof(NxusCheatInsn);
    if (out_length != NULL) *out_length = offset;
    return w->buf;
}

/* One block, one insn: the smallest "cheat" cases. */
static void makeProgram(Wire *w, u64 program_id, u32 mode, u32 enabled, u64 address,
                        u64 value) {
    wireStart(w, program_id);
    const u32 block = wireBlock(w, mode, enabled);
    wireInsn(w, block, insnStore(address, 4, value));
}

/* ---- helpers ------------------------------------------------------------ */

static void fresh(void) {
    nxusCheatSrvExit();
    cheatTestReset();
    nxusCheatSrvInit();
}

static bool uploadWire(Wire *w) {
    u32 length = 0;
    const void *wire = wireBuild(w, &length);
    NxusCheatUploadReply reply;
    return nxusCheatSrvUpload(wire, length, &reply);
}

static bool uploadWireReply(Wire *w, NxusCheatUploadReply *reply) {
    u32 length = 0;
    const void *wire = wireBuild(w, &length);
    return nxusCheatSrvUpload(wire, length, reply);
}

static NxusCheatStatus statusNow(void) {
    NxusCheatStatus st;
    memset(&st, 0, sizeof(st));
    nxusCheatSrvStatus(&st);
    return st;
}

static bool setEnabled(u32 index, bool enabled) {
    NxusCheatEnable req;
    req.index = index;
    req.enabled = enabled ? 1u : 0u;
    return nxusCheatSrvSetEnabled(&req);
}

/* ---- 1. upload validation ----------------------------------------------- */

static void testUploadValidation(void) {
    printf("[test] upload: interpreter validation, target stamp, refused-upload isolation\n");
    fresh();

    /* Wire shapes the dispatcher sends back (protocol parity is checked in
     * test_protocol_parity.py; these are the ones this service fills). */
    CHECK(sizeof(NxusCheatUploadReply) == 16, "upload reply is 16 bytes");
    CHECK(sizeof(NxusCheatStatus) == 48, "status is 48 bytes");
    CHECK(sizeof(NxusCheatRestore) == 16, "restore reply is 16 bytes");

    Wire w;
    NxusCheatUploadReply reply;

    makeProgram(&w, CHEAT_TEST_TITLE_A, 0, 1, CHEAT_TEST_BASE + 0x100, 0x11223344u);
    CHECK(uploadWireReply(&w, &reply), "a program for the current target is accepted");
    CHECK(reply.accepted_blocks == 1 && reply.accepted_insns == 1 && reply.rejected_reason == 0,
          "reply counts: blocks=%u insns=%u reason=%u", (unsigned)reply.accepted_blocks,
          (unsigned)reply.accepted_insns, (unsigned)reply.rejected_reason);

    NxusCheatStatus st = statusNow();
    CHECK(st.program_valid == 1 && st.block_count == 1 && st.insn_count == 1,
          "status reports the installed program (valid=%u blocks=%u insns=%u)",
          (unsigned)st.program_valid, (unsigned)st.block_count, (unsigned)st.insn_count);
    CHECK(st.running == 0, "running == 0 when no worker thread could be created");
    CHECK(st.journal_count == 0 && st.enabled_count == 1 && st.tick_count == 0,
          "fresh upload: no journal, upload-time enable honoured, no ticks yet");

    /* A program built for another title must be refused, and the installed one
     * must survive the refusal untouched (install validates before it writes). */
    makeProgram(&w, CHEAT_TEST_TITLE_B, 0, 1, CHEAT_TEST_BASE + 0x100, 0x55667788u);
    CHECK(!uploadWireReply(&w, &reply), "a program for another title is refused");
    CHECK(reply.rejected_reason == (u32)(-NXUS_CHEATVM_ERR_BAD_PROGRAM),
          "refusal reason is the interpreter's BAD_PROGRAM (%u)",
          (unsigned)reply.rejected_reason);
    st = statusNow();
    CHECK(st.block_count == 1 && st.insn_count == 1 && st.journal_count == 0,
          "the refused upload left the installed program untouched");

    /* Interpreter rejections travel as the positive error code. */
    makeProgram(&w, CHEAT_TEST_TITLE_A, 0, 1, CHEAT_TEST_BASE + 0x100, 1);
    w.header.magic = 0;
    CHECK(!uploadWireReply(&w, &reply), "bad magic is refused");
    CHECK(reply.rejected_reason == (u32)(-NXUS_CHEATVM_ERR_BAD_PROGRAM),
          "bad magic reports BAD_PROGRAM (%u)", (unsigned)reply.rejected_reason);

    makeProgram(&w, CHEAT_TEST_TITLE_A, 0, 1, CHEAT_TEST_BASE + 0x100, 1);
    {
        u32 length = 0;
        (void)wireBuild(&w, &length);
        /* Corrupt the header IN the payload: wireBuild() recomputes total_bytes from
           the real counts, so the lie has to be written afterwards. */
        w.header.total_bytes = length + 8u;
        memcpy(w.buf, &w.header, sizeof(w.header));
        CHECK(!nxusCheatSrvUpload(w.buf, length, &reply), "total_bytes mismatch is refused");
        /* core/nxus_cheatvm.c:install() numbers its own rejections -1..-5 and the
         * header only names the interpreter errors, so -2 ("size") is checked as
         * its positive wire code.  That encoding is the contract the reply header
         * documents ("the negative NXUS_CHEATVM_ERR_* as a positive code"). */
        CHECK(reply.rejected_reason == 2u,
              "length mismatch reports install's size error (%u)", (unsigned)reply.rejected_reason);
    }

    CHECK(!nxusCheatSrvUpload(NULL, 0, &reply), "NULL wire is refused");
    CHECK(!nxusCheatSrvUpload(NULL, 0, NULL), "NULL reply pointer is tolerated");

    /* No target: a client cannot have resolved an address, so nothing may install. */
    cheatTestSetIdentity(0, 0);
    makeProgram(&w, 0, 0, 1, CHEAT_TEST_BASE + 0x100, 1);
    CHECK(!uploadWireReply(&w, &reply), "upload with no target is refused");
    cheatTestSetIdentity(CHEAT_TEST_PID_A, CHEAT_TEST_TITLE_A);
}

/* ---- 2. enable / status ------------------------------------------------- */

static void testEnableAndStatus(void) {
    printf("[test] enable: index/target checks, live status fields\n");
    fresh();

    Wire w;
    makeProgram(&w, CHEAT_TEST_TITLE_A, 1, 0, CHEAT_TEST_BASE + 0x200, 0xCAFEF00Du);
    CHECK(uploadWire(&w), "loop program installed (disabled at upload)");
    CHECK(statusNow().enabled_count == 0, "nothing is enabled yet");

    CHECK(setEnabled(0, true), "enabling block 0 succeeds");
    CHECK(statusNow().enabled_count == 1, "status counts the enabled block");

    CHECK(!setEnabled(7, true), "an index outside the program is refused");
    CHECK(statusNow().enabled_count == 1, "the refused enable changed nothing");

    CHECK(setEnabled(0, false), "disabling block 0 succeeds");
    CHECK(statusNow().enabled_count == 0, "status counts zero enabled blocks");

    /* The target changed between upload and enable: no re-arm, nothing touched. */
    cheatTestSetIdentity(CHEAT_TEST_PID_B, CHEAT_TEST_TITLE_A);
    CHECK(!setEnabled(0, true), "enable is refused after the target changed");
    CHECK(statusNow().enabled_count == 0, "the refused enable left the block disabled");
    cheatTestSetIdentity(CHEAT_TEST_PID_A, CHEAT_TEST_TITLE_A);

    /* keys_held is sampled live (the status poll must see the current pad). */
    cheatTestSetHeldMask(0x0000000000001234ull);
    const u32 mask_reads = cheatTestHeldMaskReads();
    CHECK(statusNow().keys_held == 0x1234ull, "status reports the live HID mask");
    CHECK(cheatTestHeldMaskReads() > mask_reads, "status sampled the mask (not a cached value)");

    /* No program installed at all: enable is refused. */
    nxusCheatSrvClear();
    CHECK(!setEnabled(0, true), "enable is refused without a program");
}

/* ---- 3. patch once vs loop every tick ----------------------------------- */

static void testPatchOnceAndLoop(void) {
    printf("[test] execution: a patch block runs once, a loop block every tick\n");
    fresh();

    const u64 patch_addr = CHEAT_TEST_BASE + 0x300;
    const u64 loop_addr = CHEAT_TEST_BASE + 0x304;
    Wire w;

    makeProgram(&w, CHEAT_TEST_TITLE_A, 0, 1, patch_addr, 0xAAAA5555u);
    CHECK(uploadWire(&w), "patch program installed");
    const u32 base_writes = cheatTestWrites();

    cheatSrvWorkerStep();
    CHECK(cheatTestWrites() == base_writes + 1, "the patch block wrote once");
    CHECK(cheatTestPeekU32(patch_addr) == 0xAAAA5555u, "the target holds the patched value");
    CHECK(statusNow().journal_count == 1, "the original byte is journalled");
    CHECK(statusNow().tick_count == 1, "one tick counted");

    cheatSrvWorkerStep();
    CHECK(cheatTestWrites() == base_writes + 1,
          "the patch block did not run a second time (mode 0 = once per enable)");
    CHECK(statusNow().tick_count == 2, "the worker keeps ticking while nothing runs");

    /* A loop block runs on every tick. */
    makeProgram(&w, CHEAT_TEST_TITLE_A, 1, 1, loop_addr, 0x0BADF00Du);
    CHECK(uploadWire(&w), "loop program installed");
    CHECK(cheatTestPeekU32(patch_addr) == 0u,
          "installing a new program restored the previous program's patch");

    const u32 loop_base = cheatTestWrites();
    cheatSrvWorkerStep();
    cheatSrvWorkerStep();
    CHECK(cheatTestWrites() == loop_base + 2, "the loop block wrote on both ticks");
    CHECK(cheatTestPeekU32(loop_addr) == 0x0BADF00Du, "the loop write landed");
    CHECK(statusNow().journal_count == 1, "one address is journalled for the loop block");

    CHECK(setEnabled(0, false), "loop block disabled");
    const u32 after_disable = cheatTestWrites();
    cheatSrvWorkerStep();
    CHECK(cheatTestWrites() == after_disable, "a disabled loop block does not write");
}

/* ---- 4. consecutive failures ------------------------------------------- */

static void testConsecutiveFailures(void) {
    printf("[test] failures: three ticks in a row disable the block\n");
    fresh();

    const u64 addr = CHEAT_TEST_BASE + 0x400;
    Wire w;
    makeProgram(&w, CHEAT_TEST_TITLE_A, 1, 1, addr, 0x11112222u);
    CHECK(uploadWire(&w), "loop program installed");

    cheatTestSetWritable(false);
    cheatTestClearEvents();

    cheatSrvWorkerStep();
    CHECK(statusNow().enabled_count == 1, "one failure does not disable the block");
    CHECK(statusNow().last_error == (u32)NXUS_CHEATVM_ERR_WRITE,
          "status carries the interpreter error (%u)", (unsigned)statusNow().last_error);
    CHECK(cheatTestEventCount() == 0, "one failure sends no fault event");

    cheatSrvWorkerStep();
    CHECK(statusNow().enabled_count == 1, "two failures do not disable the block");
    CHECK(cheatTestEventCount() == 0, "two failures send no fault event");

    cheatSrvWorkerStep();
    CHECK(statusNow().enabled_count == 0, "the third consecutive failure disabled the block");
    CHECK(statusNow().fault_count == 1, "the fault is counted");
    CHECK(cheatTestEventCount() == 1, "exactly one fault event was sent");
    CHECK(cheatTestLastEventType() == NxusEvent_CheatFault, "the event is CheatFault (0x%04X)",
          (unsigned)cheatTestLastEventType());
    CHECK(cheatTestLastEventLength() == sizeof(NxusCheatFault), "the event carries a NxusCheatFault");
    const NxusCheatFault *fault = cheatTestLastFault();
    CHECK(fault->reason == (u32)(-NXUS_CHEATVM_ERR_WRITE),
          "the fault reason is the interpreter's write error as a positive code (%u)",
          (unsigned)fault->reason);
    CHECK(fault->block == 0, "the fault names block 0 (%u)", (unsigned)fault->block);
    CHECK(fault->restored == 0, "nothing was restored for a write failure");

    const u32 events = cheatTestEventCount();
    cheatSrvWorkerStep();
    CHECK(cheatTestEventCount() == events, "a disabled block sends no further events");

    /* One success re-arms the window: two more failures must not disable it. */
    Wire w2;
    makeProgram(&w2, CHEAT_TEST_TITLE_A, 1, 1, addr, 0x33334444u);
    CHECK(uploadWire(&w2), "the block is re-uploaded for the recovery check");
    cheatTestSetWritable(false);
    cheatSrvWorkerStep();
    cheatSrvWorkerStep();
    cheatTestSetWritable(true);
    cheatSrvWorkerStep();
    CHECK(statusNow().last_error == 0, "a successful tick clears the reported error");
    cheatTestSetWritable(false);
    cheatSrvWorkerStep();
    cheatSrvWorkerStep();
    CHECK(statusNow().enabled_count == 1,
          "two failures after a success do not disable the block");
    cheatSrvWorkerStep();
    CHECK(statusNow().enabled_count == 0, "the third failure after the success disables it");
}

/* ---- 5. target changed -------------------------------------------------- */

static void testTargetGone(void) {
    printf("[test] target change: stop all, restore, one TARGET_GONE event\n");
    fresh();

    const u64 addr = CHEAT_TEST_BASE + 0x500;
    const u32 original = 0x0F0F0F0Fu;
    cheatTestPoke(addr, &original, sizeof(original));

    Wire w;
    makeProgram(&w, CHEAT_TEST_TITLE_A, 0, 1, addr, 0xDEADBEEFu);
    CHECK(uploadWire(&w), "patch program installed");
    cheatSrvWorkerStep();
    CHECK(cheatTestPeekU32(addr) == 0xDEADBEEFu, "the patch is applied");
    CHECK(statusNow().journal_count == 1, "the original byte is journalled");

    cheatTestClearEvents();
    cheatTestLogClear();
    const u32 writes_before = cheatTestWrites();

    /* Same title, different pid: a relaunch. */
    cheatTestSetIdentity(CHEAT_TEST_PID_B, CHEAT_TEST_TITLE_A);
    cheatSrvWorkerStep();

    CHECK(cheatTestPeekU32(addr) == original, "the original bytes were written back");
    CHECK(cheatTestWrites() == writes_before + 1, "exactly one restore write happened");
    CHECK(statusNow().journal_count == 0, "the journal was dropped after the restore");
    CHECK(statusNow().enabled_count == 0, "every block was disabled");
    CHECK(statusNow().program_valid == 1, "the program itself is still installed");
    CHECK(statusNow().fault_count == 1, "the fault is counted");
    CHECK(cheatTestEventCount() == 1, "exactly one event was sent");
    CHECK(cheatTestLastEventType() == NxusEvent_CheatFault, "it is a CheatFault event");
    const NxusCheatFault *fault = cheatTestLastFault();
    CHECK(fault->reason == NXUS_CHEAT_FAULT_TARGET_GONE, "reason is TARGET_GONE (%u)",
          (unsigned)fault->reason);
    CHECK(fault->block == 0xFFFFFFFFu, "block is 0xFFFFFFFF (not block specific)");
    CHECK(fault->restored == 1, "the event reports the one restored address");
    CHECK(strstr(cheatTestLastLog(), "target changed") != NULL,
          "the log line names the target change: \"%s\"", cheatTestLastLog());

    /* Nothing runs again until a re-upload. */
    const u32 writes_after_fault = cheatTestWrites();
    cheatSrvWorkerStep();
    CHECK(cheatTestWrites() == writes_after_fault, "a faulted program never ticks again");
    CHECK(!setEnabled(0, true), "enable is refused after the fault");
    CHECK(setEnabled(0, false), "disabling is still accepted after the fault");

    /* Re-uploading for the target that is actually running works. */
    Wire w2;
    makeProgram(&w2, CHEAT_TEST_TITLE_A, 0, 1, addr, 0x12345678u);
    CHECK(uploadWire(&w2), "a re-upload for the current target is accepted");
    cheatSrvWorkerStep();
    CHECK(cheatTestPeekU32(addr) == 0x12345678u, "the re-uploaded program runs");

    /* The same rule, driven by the dmnt incarnation only (fixed-layout restart:
       same pid, same title). */
    fresh();
    cheatTestPoke(addr, &original, sizeof(original));
    Wire w3;
    makeProgram(&w3, CHEAT_TEST_TITLE_A, 0, 1, addr, 0xA5A5A5A5u);
    CHECK(uploadWire(&w3), "second program installed");
    cheatSrvWorkerStep();
    CHECK(cheatTestPeekU32(addr) == 0xA5A5A5A5u, "second program patched its address");
    cheatTestClearEvents();
    cheatTestSetIncarnation(2);          /* same pid, same title, new process */
    cheatSrvWorkerStep();
    CHECK(cheatTestPeekU32(addr) == original, "an incarnation change restores the original");
    CHECK(statusNow().enabled_count == 0, "an incarnation change disables every block");
    CHECK(cheatTestEventCount() == 1 && cheatTestLastFault()->reason == NXUS_CHEAT_FAULT_TARGET_GONE,
          "an incarnation change reports TARGET_GONE");

    /* A title change with the pid reused (pid is the same, title moved). */
    fresh();
    Wire w4;
    makeProgram(&w4, CHEAT_TEST_TITLE_A, 0, 0, addr, 1);
    CHECK(uploadWire(&w4), "third program installed");
    cheatTestSetIdentity(CHEAT_TEST_PID_A, CHEAT_TEST_TITLE_B);
    cheatTestClearEvents();
    cheatSrvWorkerStep();
    CHECK(cheatTestEventCount() == 1 && cheatTestLastFault()->reason == NXUS_CHEAT_FAULT_TARGET_GONE,
          "a reused pid with a new title reports TARGET_GONE");

    /* Losing the target entirely (pid 0) is a mismatch, never a match. */
    fresh();
    Wire w5;
    makeProgram(&w5, CHEAT_TEST_TITLE_A, 1, 1, addr, 0x11111111u);
    CHECK(uploadWire(&w5), "fourth program installed");
    cheatSrvWorkerStep();
    cheatTestSetIdentity(0, 0);
    cheatTestClearEvents();
    cheatSrvWorkerStep();
    CHECK(cheatTestEventCount() == 1 && cheatTestLastFault()->reason == NXUS_CHEAT_FAULT_TARGET_GONE,
          "an empty identity reports TARGET_GONE");
}

/* ---- 6. PanicOff -------------------------------------------------------- */

static void testPanicOff(void) {
    printf("[test] panic off: restore accounting, retry after a partial failure\n");
    fresh();

    const u64 addr_a = CHEAT_TEST_BASE + 0x600;
    const u64 addr_b = CHEAT_TEST_BASE + 0x604;
    const u32 original_a = 0x1111AAAAu;
    const u32 original_b = 0x2222BBBBu;
    cheatTestPoke(addr_a, &original_a, sizeof(original_a));
    cheatTestPoke(addr_b, &original_b, sizeof(original_b));

    Wire w;
    wireStart(&w, CHEAT_TEST_TITLE_A);
    const u32 block_a = wireBlock(&w, 0, 1);
    wireInsn(&w, block_a, insnStore(addr_a, 4, 0xCCCCCCCCu));
    const u32 block_b = wireBlock(&w, 1, 1);
    wireInsn(&w, block_b, insnStore(addr_b, 4, 0xDDDDDDDDu));
    CHECK(uploadWire(&w), "two-block program installed");
    cheatSrvWorkerStep();
    CHECK(statusNow().journal_count == 2, "both addresses are journalled");

    NxusCheatRestore rs;
    nxusCheatSrvPanicOff(&rs);
    CHECK(rs.blocks_stopped == 2, "panic off reports the two stopped blocks (%u)",
          (unsigned)rs.blocks_stopped);
    CHECK(rs.restored == 2 && rs.failed == 0, "panic off restored both addresses (%u/%u)",
          (unsigned)rs.restored, (unsigned)rs.failed);
    CHECK(cheatTestPeekU32(addr_a) == original_a, "address A is back to its original value");
    CHECK(cheatTestPeekU32(addr_b) == original_b, "address B is back to its original value");
    CHECK(statusNow().journal_count == 0, "the journal is empty after a clean restore");
    CHECK(statusNow().enabled_count == 0, "nothing is enabled after panic off");

    nxusCheatSrvPanicOff(&rs);
    CHECK(rs.restored == 0 && rs.failed == 0 && rs.blocks_stopped == 0,
          "a second panic off is a no-op");

    /* A target that refuses the write-back: the journal must survive for a retry. */
    CHECK(setEnabled(0, true) && setEnabled(1, true), "both blocks re-enabled");
    cheatSrvWorkerStep();
    CHECK(statusNow().journal_count == 2, "the blocks patched their addresses again");
    cheatTestSetWritable(false);
    nxusCheatSrvPanicOff(&rs);
    CHECK(rs.restored == 0 && rs.failed == 2,
          "a failed restore is reported, not hidden (%u restored, %u failed)",
          (unsigned)rs.restored, (unsigned)rs.failed);
    CHECK(statusNow().journal_count == 2, "the journal is kept for a retry");
    cheatTestSetWritable(true);
    nxusCheatSrvPanicOff(&rs);
    CHECK(rs.restored == 2 && rs.failed == 0, "the retry restored both addresses");
    CHECK(statusNow().journal_count == 0, "the journal is cleared after the retry succeeded");
}

/* ---- 7. Clear ----------------------------------------------------------- */

static void testClear(void) {
    printf("[test] clear: drop the program without writing to the target\n");
    fresh();

    const u64 addr = CHEAT_TEST_BASE + 0x700;
    Wire w;
    makeProgram(&w, CHEAT_TEST_TITLE_A, 0, 1, addr, 0x77777777u);
    CHECK(uploadWire(&w), "program installed");
    cheatSrvWorkerStep();
    const u32 writes = cheatTestWrites();
    CHECK(cheatTestPeekU32(addr) == 0x77777777u, "the patch is applied");

    cheatTestLogClear();
    nxusCheatSrvClear();
    CHECK(statusNow().program_valid == 0, "clear drops the program");
    CHECK(statusNow().block_count == 0 && statusNow().insn_count == 0, "no blocks/insns left");
    CHECK(statusNow().journal_count == 0, "the journal is gone");
    CHECK(cheatTestWrites() == writes, "clear wrote nothing to the target");
    CHECK(cheatTestPeekU32(addr) == 0x77777777u, "the patch stays applied (documented)");
    CHECK(strstr(cheatTestLastLog(), "without writing back") != NULL,
          "the log line warns that the patch was not undone: \"%s\"", cheatTestLastLog());

    cheatSrvWorkerStep();
    CHECK(cheatTestWrites() == writes, "nothing ticks after a clear");
}

/* ---- 8. IO adapter ------------------------------------------------------ */

static void testIoAdapterPolicy(void) {
    printf("[test] IO adapter: allow_rx uses the RX-patch policy, refusal means no write\n");
    fresh();

    const u64 addr = CHEAT_TEST_BASE + 0x800;
    Wire w;
    makeProgram(&w, CHEAT_TEST_TITLE_A, 1, 1, addr, 0xABCDEF01u);
    CHECK(uploadWire(&w), "loop program installed");

    cheatTestSetRangeAllowed(false);
    cheatTestClearEvents();
    cheatSrvWorkerStep();
    CHECK(cheatTestWrites() == 0, "a refused range means no write at all");
    CHECK(cheatTestWritesOk() == 0, "no accepted write either");
    CHECK(cheatTestPatchRangeChecks() >= 1,
          "the ALLOW_RX (code-patch) policy gated the write (%u checks)",
          (unsigned)cheatTestPatchRangeChecks());
    CHECK(cheatTestPlainRangeChecks() == 0,
          "the plain writable policy was not used (%u checks)",
          (unsigned)cheatTestPlainRangeChecks());
    CHECK(statusNow().last_error == (u32)NXUS_CHEATVM_ERR_WRITE,
          "the interpreter reports the refused write");

    /* The 3-tick rule covers a range refusal too: the address is simply not
       writable for this program. */
    cheatSrvWorkerStep();
    cheatSrvWorkerStep();
    CHECK(statusNow().enabled_count == 0, "a permanently refused range disables the block");
    CHECK(cheatTestEventCount() == 1, "and reports it once");
    CHECK(cheatTestLastFault()->reason == (u32)(-NXUS_CHEATVM_ERR_WRITE),
          "the reported reason is the write error (%u)",
          (unsigned)cheatTestLastFault()->reason);

    /* One validated range is reused inside a tick: a loop that writes the same
     * address repeatedly asks the live target once, not once per store. */
    fresh();
    Wire w2;
    wireStart(&w2, CHEAT_TEST_TITLE_A);
    const u32 block = wireBlock(&w2, 1, 1);
    /* LoopStart r0 = 4 iterations of "store the same address", LoopEnd.  The
       linked form is what the PC uploads; the interpreter only runs it. */
    {
        NxusCheatInsn start;
        memset(&start, 0, sizeof(start));
        start.op = (u16)NxusCheatOp_LoopStart;
        start.reg_a = 0;
        start.value = 4;
        start.target = 1;
        wireInsn(&w2, block, start);
        wireInsn(&w2, block, insnStore(addr, 4, 0x01010101u));
        NxusCheatInsn end;
        memset(&end, 0, sizeof(end));
        end.op = (u16)NxusCheatOp_LoopEnd;
        end.reg_a = 0;
        end.target = 0;
        wireInsn(&w2, block, end);
    }
    CHECK(uploadWire(&w2), "loop program installed");
    cheatSrvWorkerStep();
    CHECK(cheatTestWrites() == 4, "four iterations wrote the address (%u writes)",
          (unsigned)cheatTestWrites());
    CHECK(cheatTestPatchRangeChecks() == 1,
          "the validated range was reused inside the tick (%u live queries)",
          (unsigned)cheatTestPatchRangeChecks());
}

/* ---- 9. HID mask -------------------------------------------------------- */

static void testHeldMask(void) {
    printf("[test] HID: the mask is sampled on every tick and key codes react live\n");
    fresh();

    const u64 addr = CHEAT_TEST_BASE + 0x900;
    Wire w;
    wireStart(&w, CHEAT_TEST_TITLE_A);
    const u32 block = wireBlock(&w, 1, 1);
    /* KeyConditional(mask) -> store -> nop; when the combo is not held it jumps
       over the store to the nop. */
    wireInsn(&w, block, insnKeypress(0x0000000000000010ull, 2));
    wireInsn(&w, block, insnStore(addr, 4, 0x42424242u));
    wireInsn(&w, block, insnNop());
    CHECK(uploadWire(&w), "key-conditional program installed");

    cheatTestSetHeldMask(0x0000000000000010ull);
    cheatSrvWorkerStep();
    CHECK(cheatTestPeekU32(addr) == 0x42424242u, "the store runs while the combo is held");

    const u32 held_reads = cheatTestHeldMaskReads();
    cheatTestSetHeldMask(0);
    const u32 writes = cheatTestWrites();
    cheatSrvWorkerStep();
    /* Two samples per tick: one handed to the interpreter (key conditionals) and
       one for the status snapshot it republishes. */
    CHECK(cheatTestHeldMaskReads() >= held_reads + 2, "the mask is read on every tick");
    CHECK(cheatTestWrites() == writes, "the store is skipped while the combo is released");

    cheatTestSetHeldMask(0x0000000000000010ull);
    cheatSrvWorkerStep();
    CHECK(cheatTestWrites() == writes + 1, "the store runs again when the combo returns");
}

/* ---- 10. lifecycle ------------------------------------------------------ */

static void testLifecycle(void) {
    printf("[test] lifecycle: server gate, init/exit idempotence, statics\n");
    fresh();

    CHECK(cheatWorkerShouldRun(), "the worker loop runs while the server is up");
    cheatTestSetServerExited(true);
    CHECK(!cheatWorkerShouldRun(), "the dispatcher's terminal gate stops the worker");
    cheatTestSetServerExited(false);
    CHECK(cheatWorkerShouldRun(), "clearing the gate lets the worker run again");
    nxusCheatSrvExit();
    CHECK(!cheatWorkerShouldRun(), "exit stops the worker loop");
    /* The service is terminal until the next Init: a client that keeps polling must
       not be able to install a program behind the release. */
    {
        Wire refused;
        makeProgram(&refused, CHEAT_TEST_TITLE_A, 1, 1, CHEAT_TEST_BASE + 0xC00, 1);
        CHECK(!uploadWire(&refused), "upload is refused after exit");
        CHECK(!setEnabled(0, true), "enable is refused after exit");
        NxusCheatStatus exited_status = statusNow();
        CHECK(exited_status.program_valid == 0,
              "status reports no program after exit");
    }
    nxusCheatSrvExit();                       /* documented as a no-op */
    CHECK(!cheatWorkerShouldRun(), "a second exit changes nothing");
    nxusCheatSrvInit();
    CHECK(cheatWorkerShouldRun(), "a re-init starts the loop again");
    {
        Wire accepted;
        makeProgram(&accepted, CHEAT_TEST_TITLE_A, 1, 1, CHEAT_TEST_BASE + 0xC00, 1);
        CHECK(uploadWire(&accepted), "a re-init accepts uploads again");
    }
    nxusCheatSrvInit();                       /* documented as a no-op */
    CHECK(cheatWorkerShouldRun(), "a second init changes nothing");

    /* The static budget the header documents (the asserts in the shipped .c make
       the build fail if a core cap pushes it out). */
    const u32 footprint = (u32)(sizeof(NxusCheatProgram) + sizeof(NxusCheatJournal) +
                                sizeof(g_WorkerStack));
    CHECK(footprint <= 40u * 1024u, "cheat service statics fit the declared budget (%u B)",
          (unsigned)footprint);
    CHECK(sizeof(NxusCheatProgram) + sizeof(NxusCheatJournal) == 29888u,
          "program + journal are 29888 B (program %u, journal %u)",
          (unsigned)sizeof(NxusCheatProgram), (unsigned)sizeof(NxusCheatJournal));

    /* The identity sample may fail (a writer held the seqlock); that must skip the
       tick, never run unverified. */
    Wire w;
    makeProgram(&w, CHEAT_TEST_TITLE_A, 1, 1, CHEAT_TEST_BASE + 0xA00, 0x99999999u);
    CHECK(uploadWire(&w), "program installed");
    const u32 writes = cheatTestWrites();
    cheatTestSetIdentityBroken(true);
    cheatSrvWorkerStep();
    CHECK(cheatTestWrites() == writes, "an unverifiable identity skips the tick");
    cheatTestSetIdentityBroken(false);
    cheatSrvWorkerStep();
    CHECK(cheatTestWrites() == writes + 1, "a verifiable identity runs the tick");

    /* Debug mode suspends the cheat engine (dmnt is closed then) and says so once
       per transition. */
    fresh();
    Wire w2;
    makeProgram(&w2, CHEAT_TEST_TITLE_A, 1, 1, CHEAT_TEST_BASE + 0xB00, 0x0A0A0A0Au);
    CHECK(uploadWire(&w2), "program installed for the debug-suspension check");
    cheatTestSetDebugAttached(true);
    cheatTestLogClear();
    const u32 debug_writes = cheatTestWrites();
    cheatSrvWorkerStep();
    CHECK(cheatTestWrites() == debug_writes, "no block runs while a debug session is attached");
    CHECK(strstr(cheatTestLastLog(), "suspended") != NULL,
          "the suspension is logged once: \"%s\"", cheatTestLastLog());
    cheatTestSetDebugAttached(false);
    cheatTestLogClear();
    cheatSrvWorkerStep();
    CHECK(strstr(cheatTestLastLog(), "resumes") != NULL,
          "the resumption is logged once: \"%s\"", cheatTestLastLog());
    CHECK(cheatTestWrites() == debug_writes + 1, "the cheat runs again after the debug detach");
}

int main(void) {
    printf("== Nxus cheat service host tests ==\n");
    testUploadValidation();
    testEnableAndStatus();
    testPatchOnceAndLoop();
    testConsecutiveFailures();
    testTargetGone();
    testPanicOff();
    testClear();
    testIoAdapterPolicy();
    testHeldMask();
    testLifecycle();

    nxusCheatSrvExit();
    printf("\n%d checks, %d failure(s)\n", g_checks, g_failures);
    if (g_failures != 0) {
        printf("CHEAT SERVICE TESTS FAILED\n");
        return 1;
    }
    printf("ALL CHEAT SERVICE TESTS PASSED\n");
    return 0;
}
