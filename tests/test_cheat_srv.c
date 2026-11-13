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
 *   - the upload dispatch: a PATCH-ONLY program (every block mode == 0) is executed
 *     once during the upload (plan/apply pass, journal included) and its scratch
 *     program is released - it never becomes resident and never replaces a running
 *     loop program; a program WITH a loop block becomes resident, and a re-upload
 *     restores the old journal, releases the old instruction array and keeps the
 *     old program on a failed install (NO_MEMORY / validation),
 *   - the heap lifetime of the instruction array: patch uploads are balanced,
 *     re-upload / Clear / Exit release the resident array (allocator counter),
 *   - the target stamp: a pid / title / dmnt-incarnation change stops every block,
 *     writes the journalled originals back, drops the journal and publishes exactly
 *     one NxusEvent_CheatFault(NXUS_CHEAT_FAULT_TARGET_GONE); no further tick runs
 *     until a re-upload,
 *   - the 3-tick auto-disable: two failures keep a block alive, the third disables
 *     it and reports the interpreter error, and one success re-arms the window,
 *   - the journal-full path (immediate disable, NXUS_CHEAT_FAULT_JOURNAL_FULL),
 *   - PanicOff: restored/failed/blocks_stopped, a partial failure that keeps the
 *     journal for a retry, the second call being a no-op, and the write-back of a
 *     patch-only upload (no resident program, journal is still the truth),
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
#include <stdlib.h>
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

/* ---- instruction-array allocator spy ------------------------------------ *
 * nxusCheatSetAllocator() (core/nxus_cheatvm.h) lets the test count installs and
 * releases and remember the pointers that were freed, which is what makes
 * "a patch-only upload does not leak" and "a re-upload frees the OLD array"
 * observable instead of inferred.  Every program stores the free function that
 * produced its buffer, so restoring the default allocator later cannot mismatch.
 */
static u32  g_Allocs;
static u32  g_Frees;
static void *g_Freed[32];
static u32  g_FreedCount;

static void *testAlloc(size_t size, void *user) {
    (void)user;
    g_Allocs++;
    return malloc(size);
}

static void testFree(void *ptr, void *user) {
    (void)user;
    if (ptr != NULL) {
        if (g_FreedCount < (u32)(sizeof(g_Freed) / sizeof(g_Freed[0]))) {
            g_Freed[g_FreedCount] = ptr;
        }
        g_FreedCount++;
        g_Frees++;
        free(ptr);
    }
}

static void *failAlloc(size_t size, void *user) {
    (void)size;
    (void)user;
    g_Allocs++;
    return NULL;
}

static void allocatorBegin(void) {
    g_Allocs = 0;
    g_Frees = 0;
    g_FreedCount = 0;
    memset(g_Freed, 0, sizeof(g_Freed));
    nxusCheatSetAllocator(testAlloc, testFree, NULL);
}

static void allocatorEnd(void) {
    nxusCheatSetAllocator(NULL, NULL, NULL);
}

static bool freedContains(const void *ptr) {
    u32 i;
    for (i = 0; i < g_FreedCount && i < (u32)(sizeof(g_Freed) / sizeof(g_Freed[0])); i++) {
        if (g_Freed[i] == ptr) return true;
    }
    return false;
}

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

    /* A loop block keeps the program resident, which is what the status checks
     * below describe (a patch-only upload is executed and released instead). */
    makeProgram(&w, CHEAT_TEST_TITLE_A, 1, 1, CHEAT_TEST_BASE + 0x100, 0x11223344u);
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

    /* One loop block anywhere keeps the whole program resident, so a patch block
     * that travels WITH a loop stays on the worker path: it runs once on the first
     * tick (mode 0 = once per enable) while the loop block runs every tick.  A
     * patch-only program never gets here - it is executed during the upload and
     * released (see testPatchOnlyUpload). */
    wireStart(&w, CHEAT_TEST_TITLE_A);
    const u32 patch_block = wireBlock(&w, 0, 1);
    wireInsn(&w, patch_block, insnStore(patch_addr, 4, 0xAAAA5555u));
    const u32 loop_block = wireBlock(&w, 1, 1);
    wireInsn(&w, loop_block, insnStore(loop_addr, 4, 0x0BADF00Du));
    CHECK(uploadWire(&w), "patch + loop program installed");
    CHECK(statusNow().program_valid == 1 && statusNow().block_count == 2 &&
          statusNow().insn_count == 2,
          "a program with a loop block is resident (valid=%u blocks=%u insns=%u)",
          (unsigned)statusNow().program_valid, (unsigned)statusNow().block_count,
          (unsigned)statusNow().insn_count);
    CHECK(cheatTestPeekU32(patch_addr) == 0u && cheatTestPeekU32(loop_addr) == 0u,
          "the upload itself executed nothing");

    const u32 base_writes = cheatTestWrites();

    cheatSrvWorkerStep();
    CHECK(cheatTestWrites() == base_writes + 2,
          "the first tick applied the patch block and the loop block (%u writes)",
          (unsigned)(cheatTestWrites() - base_writes));
    CHECK(cheatTestPeekU32(patch_addr) == 0xAAAA5555u, "the target holds the patched value");
    CHECK(cheatTestPeekU32(loop_addr) == 0x0BADF00Du, "the loop write landed");
    CHECK(statusNow().journal_count == 2, "both originals are journalled");
    CHECK(statusNow().tick_count == 1, "one tick counted");

    cheatSrvWorkerStep();
    CHECK(cheatTestWrites() == base_writes + 2,
          "the patch block did not run a second time (mode 0 = once per enable); the "
          "loop found its value already applied");
    CHECK(statusNow().tick_count == 2, "the worker keeps ticking while nothing writes");

    /* A loop block runs on every tick. */
    makeProgram(&w, CHEAT_TEST_TITLE_A, 1, 1, loop_addr, 0x0BADF00Du);
    CHECK(uploadWire(&w), "loop program installed");
    CHECK(cheatTestPeekU32(patch_addr) == 0u,
          "installing a new program restored the previous program's patch");

    const u32 loop_base = cheatTestWrites();
    /* The upload restored the previous program's journal (inside a freeze), so
     * count pauses from here: the data loop itself must add none. */
    const u32 pauses_base = cheatTestPauses();
    cheatSrvWorkerStep();
    CHECK(cheatTestWrites() == loop_base + 1, "the first tick applied the loop value");
    cheatSrvWorkerStep();
    CHECK(cheatTestWrites() == loop_base + 1,
          "the second tick found the value already applied and wrote nothing");
    CHECK(cheatTestPeekU32(loop_addr) == 0x0BADF00Du, "the loop write landed");
    CHECK(statusNow().journal_count == 1, "one address is journalled for the loop block");
    CHECK(cheatTestPauses() == pauses_base, "a data-only loop block never pauses the target");

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
    /* Move the target value so the next ticks really try to write: an already
     * applied value is skipped (and must not count as a failure). */
    {
        const u32 moved = 0x77770000u;
        cheatTestPoke(addr, &moved, sizeof(moved));
    }
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
    makeProgram(&w, CHEAT_TEST_TITLE_A, 1, 1, addr, 0xDEADBEEFu);
    CHECK(uploadWire(&w), "loop program installed");
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
    makeProgram(&w2, CHEAT_TEST_TITLE_A, 1, 1, addr, 0x12345678u);
    CHECK(uploadWire(&w2), "a re-upload for the current target is accepted");
    cheatSrvWorkerStep();
    CHECK(cheatTestPeekU32(addr) == 0x12345678u, "the re-uploaded program runs");

    /* The same rule, driven by the dmnt incarnation only (fixed-layout restart:
       same pid, same title). */
    fresh();
    cheatTestPoke(addr, &original, sizeof(original));
    Wire w3;
    makeProgram(&w3, CHEAT_TEST_TITLE_A, 1, 1, addr, 0xA5A5A5A5u);
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
    makeProgram(&w4, CHEAT_TEST_TITLE_A, 1, 0, addr, 1);
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
    makeProgram(&w, CHEAT_TEST_TITLE_A, 1, 1, addr, 0x77777777u);
    CHECK(uploadWire(&w), "loop program installed");
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
    /* The plan pass sees the first iteration is needed and the next three would
     * write the same bytes; the apply pass writes once and skips the rest. */
    CHECK(cheatTestWrites() == 1, "only the first differing write is issued (%u writes)",
          (unsigned)cheatTestWrites());
    CHECK(cheatTestPatchRangeChecks() == 1,
          "the validated range was reused across BOTH passes (%u live queries)",
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

    /* The value written while the combo was held is still there, so the store is
     * skipped; only a target that lost the value causes another write. */
    cheatTestSetHeldMask(0x0000000000000010ull);
    cheatSrvWorkerStep();
    CHECK(cheatTestWrites() == writes, "an already-correct value is not rewritten");
    {
        const u32 stale = 0u;
        cheatTestPoke(addr, &stale, sizeof(stale));
    }
    cheatSrvWorkerStep();
    CHECK(cheatTestWrites() == writes + 1,
          "the store runs again when the combo returns and the value differs");
}

/* ---- 10. RX freeze ------------------------------------------------------ */

static void testFreeze(void) {
    printf("[test] freeze: RX blocks run inside dmnt Pause/Resume, never half-written\n");

    const u64 code_addr = CHEAT_TEST_BASE + 0xD00;
    const u64 data_addr = CHEAT_TEST_BASE + 0xD80;

    /* 1. An RX block is pause -> write -> resume. */
    fresh();
    cheatTestSetRxRange(code_addr, 8);
    {
        Wire w;
        makeProgram(&w, CHEAT_TEST_TITLE_A, 1, 1, code_addr, 0xFEEDFACEu);
        CHECK(uploadWire(&w), "RX loop program installed");
    }
    cheatTestCallLogClear();
    cheatTestClearEvents();
    cheatSrvWorkerStep();
    CHECK(cheatTestPeekU32(code_addr) == 0xFEEDFACEu, "the RX value was written");
    CHECK(cheatTestPauses() == 1 && cheatTestResumes() == 1,
          "exactly one Pause/Resume pair (%u/%u)",
          (unsigned)cheatTestPauses(), (unsigned)cheatTestResumes());
    CHECK(strcmp(cheatTestCallLog(), "PWR") == 0,
          "the call order is Pause -> Write -> Resume (\"%s\")", cheatTestCallLog());
    CHECK(cheatTestEventCount() == 0, "a frozen RX block reports no fault");

    /* 2. The next tick finds the value already applied: no write, no pause. */
    cheatTestCallLogClear();
    cheatSrvWorkerStep();
    CHECK(cheatTestWrites() == 1, "the steady-state tick wrote nothing (%u writes)",
          (unsigned)cheatTestWrites());
    CHECK(cheatTestPauses() == 1 && cheatTestResumes() == 1,
          "and did not freeze the target again (%u/%u)",
          (unsigned)cheatTestPauses(), (unsigned)cheatTestResumes());
    CHECK(cheatTestCallLog()[0] == '\0', "the steady-state tick made no Pause/Write/Resume call");

    /* 3. A data-only block never pauses. */
    fresh();
    {
        Wire w;
        makeProgram(&w, CHEAT_TEST_TITLE_A, 1, 1, data_addr, 0x12345678u);
        CHECK(uploadWire(&w), "data loop program installed");
    }
    cheatSrvWorkerStep();
    CHECK(cheatTestPeekU32(data_addr) == 0x12345678u, "the data value was written");
    CHECK(cheatTestPauses() == 0 && cheatTestResumes() == 0,
          "a data-only block does not pause (%u/%u)",
          (unsigned)cheatTestPauses(), (unsigned)cheatTestResumes());

    /* 4. Pause failure: zero writes, block disabled, CANNOT_FREEZE fault. */
    fresh();
    cheatTestSetRxRange(code_addr, 8);
    {
        Wire w;
        makeProgram(&w, CHEAT_TEST_TITLE_A, 1, 1, code_addr, 0xDEADBEEFu);
        CHECK(uploadWire(&w), "RX program installed for the pause-failure check");
    }
    cheatTestSetPauseFails(true);
    cheatTestClearEvents();
    cheatSrvWorkerStep();
    CHECK(cheatTestPeekU32(code_addr) == 0u, "a failed Pause means no code was written");
    CHECK(cheatTestWrites() == 0, "not a single write was issued (%u)",
          (unsigned)cheatTestWrites());
    CHECK(cheatTestPauses() == 1 && cheatTestResumes() == 0,
          "a failed Pause is not followed by a Resume (%u/%u)",
          (unsigned)cheatTestPauses(), (unsigned)cheatTestResumes());
    CHECK(statusNow().enabled_count == 0, "the unfreezable RX block was disabled");
    CHECK(cheatTestEventCount() == 1,
          "the refused block reports exactly one event (%u)", (unsigned)cheatTestEventCount());
    CHECK(cheatTestLastFault()->reason == NXUS_CHEAT_FAULT_CANNOT_FREEZE,
          "the fault reason is CANNOT_FREEZE (%u)", (unsigned)cheatTestLastFault()->reason);
    CHECK(cheatTestLogContains("frozen"),
          "the refusal is logged: \"%s\"", cheatTestLastLog());

    /* 5. A VM/write error inside the window still resumes. */
    fresh();
    cheatTestSetRxRange(code_addr, 8);
    {
        Wire w;
        makeProgram(&w, CHEAT_TEST_TITLE_A, 1, 1, code_addr, 0xCAFEBABEu);
        CHECK(uploadWire(&w), "RX program installed for the error-resume check");
    }
    cheatTestSetWritable(false);          /* the write itself fails */
    cheatTestCallLogClear();
    cheatSrvWorkerStep();
    CHECK(cheatTestPauses() == 1 && cheatTestResumes() == 1,
          "Resume runs even when the write fails (%u/%u)",
          (unsigned)cheatTestPauses(), (unsigned)cheatTestResumes());
    CHECK(cheatTestWrites() == 1, "the failing write was attempted once (%u)",
          (unsigned)cheatTestWrites());
    CHECK(statusNow().last_error == (u32)NXUS_CHEATVM_ERR_WRITE,
          "the interpreter error is recorded (%u)", (unsigned)statusNow().last_error);
    CHECK(strcmp(cheatTestCallLog(), "PWR") == 0,
          "the window still closes with a Resume (\"%s\")", cheatTestCallLog());

    /* 6. PanicOff freezes the restore: pause -> write originals -> resume. */
    fresh();
    cheatTestSetRxRange(code_addr, 8);
    {
        Wire w;
        makeProgram(&w, CHEAT_TEST_TITLE_A, 0, 1, code_addr, 0xA5A50001u);
        CHECK(uploadWire(&w), "RX patch applied before PanicOff");
    }
    cheatSrvWorkerStep();
    CHECK(cheatTestPeekU32(code_addr) == 0xA5A50001u, "the RX patch is in place");
    cheatTestCallLogClear();
    {
        const u32 pauses_before = cheatTestPauses();
        const u32 resumes_before = cheatTestResumes();
        NxusCheatRestore rs;
        nxusCheatSrvPanicOff(&rs);
        CHECK(rs.restored == 1 && rs.failed == 0,
              "PanicOff restored the address (%u restored, %u failed)",
              (unsigned)rs.restored, (unsigned)rs.failed);
        CHECK(cheatTestPeekU32(code_addr) == 0u, "the original code byte is back");
        CHECK(strcmp(cheatTestCallLog(), "PWR") == 0,
              "PanicOff order is Pause -> Restore -> Resume (\"%s\")", cheatTestCallLog());
        CHECK(cheatTestPauses() == pauses_before + 1 &&
              cheatTestResumes() == resumes_before + 1,
              "PanicOff paused and resumed once (%u/%u)",
              (unsigned)cheatTestPauses(), (unsigned)cheatTestResumes());
        CHECK(statusNow().journal_count == 0, "a clean restore drops the journal");
    }
    /* The second PanicOff has nothing to restore, so it must not pause. */
    {
        const u32 pauses_before = cheatTestPauses();
        const u32 resumes_before = cheatTestResumes();
        NxusCheatRestore rs;
        cheatTestCallLogClear();
        nxusCheatSrvPanicOff(&rs);
        CHECK(rs.restored == 0 && rs.failed == 0 && rs.blocks_stopped == 0,
              "a second PanicOff is a no-op");
        CHECK(cheatTestPauses() == pauses_before && cheatTestResumes() == resumes_before,
              "an empty PanicOff does not touch Pause/Resume");
    }

    /* 7. PanicOff with a failing Pause still restores, and says it ran unfrozen. */
    fresh();
    cheatTestSetRxRange(code_addr, 8);
    {
        Wire w;
        makeProgram(&w, CHEAT_TEST_TITLE_A, 0, 1, code_addr, 0xA5A50002u);
        CHECK(uploadWire(&w), "RX patch applied for the failing-freeze restore");
    }
    cheatSrvWorkerStep();
    CHECK(cheatTestPeekU32(code_addr) == 0xA5A50002u, "the RX patch is in place again");
    cheatTestSetPauseFails(true);
    cheatTestLogClear();
    {
        NxusCheatRestore rs;
        nxusCheatSrvPanicOff(&rs);
        CHECK(rs.restored == 1, "the restore still ran without the freeze (%u restored)",
              (unsigned)rs.restored);
        CHECK(rs.failed >= 1, "and is reported as failed (%u failed)", (unsigned)rs.failed);
        CHECK(cheatTestPeekU32(code_addr) == 0u, "the original byte was written back anyway");
        CHECK(cheatTestPauses() == 2 && cheatTestResumes() == 1,
              "the failed freeze was not paired with a Resume (%u/%u)",
              (unsigned)cheatTestPauses(), (unsigned)cheatTestResumes());
        CHECK(strstr(cheatTestLastLog(), "freeze") != NULL,
              "the unfrozen restore is logged: \"%s\"", cheatTestLastLog());
        /* The write-back itself succeeded, so the entry is gone: only a FAILED
         * write-back stays journalled for a retry (see testPanicOff's
         * writable=false case).  Keeping a restored address would make the next
         * PanicOff rewrite bytes that are already correct. */
        CHECK(statusNow().journal_count == 0,
              "a restored entry is removed even when the freeze failed (%u left)",
              (unsigned)statusNow().journal_count);
    }
}

/* ---- 11. lifecycle ------------------------------------------------------ */

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
       the build fail if a core cap pushes it out).  There are two program structs
       now - the resident program and the patch-upload scratch - and the plan pass
       needs its own journal: still far inside the sysmodule's 8 MiB. */
    const u32 footprint = (u32)(2u * sizeof(NxusCheatProgram) + 2u * sizeof(NxusCheatJournal) +
                                sizeof(g_WorkerStack));
    /* The instruction arrays are heap-allocated (only what was uploaded), so each
       program struct is ~5 KiB instead of carrying 2048 instructions inline. */
    CHECK(footprint <= 96u * 1024u, "cheat service statics fit the declared budget (%u B)",
          (unsigned)footprint);
    /* The instruction array is heap-allocated now (only what was uploaded), so the
       struct itself is ~5 KiB instead of ~53 KiB.  Range checks instead of an exact
       size: the point is "the program no longer carries 2048 instructions inline". */
    CHECK(sizeof(NxusCheatProgram) < 8u * 1024u,
          "the program struct no longer embeds the instructions (%u B)",
          (unsigned)sizeof(NxusCheatProgram));
    /* The journal is a heap descriptor now (the old fixed entries[512] array was
       what wedged the engine at 512 addresses).  The service allocates the entry
       arrays at Init and the interpreter grows them on demand. */
    CHECK(sizeof(NxusCheatJournal) <= 64u,
          "the journal struct is a heap descriptor (%u B)", (unsigned)sizeof(NxusCheatJournal));
    CHECK(g_Journal.entries != NULL && g_Journal.capacity == NXUS_CHEATSRV_JOURNAL_INITIAL,
          "init allocated the real journal at %u slots (cap=%u)",
          (unsigned)NXUS_CHEATSRV_JOURNAL_INITIAL, (unsigned)g_Journal.capacity);
    CHECK(g_ProbeJournal.entries != NULL &&
          g_ProbeJournal.capacity == NXUS_CHEATSRV_JOURNAL_INITIAL,
          "init allocated the plan-pass journal too (cap=%u)", (unsigned)g_ProbeJournal.capacity);
    CHECK(sizeof(g_ProbeJournal) == sizeof(NxusCheatJournal),
          "the plan journal is one more journal descriptor (%u B)",
          (unsigned)sizeof(g_ProbeJournal));

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

    /* Debug mode: dmnt is closed, so RX blocks cannot be frozen and are skipped,
       while data-only blocks keep running through the debug handle. */
    fresh();
    const u64 data_addr = CHEAT_TEST_BASE + 0xB00;
    const u64 code_addr = CHEAT_TEST_BASE + 0xB04;
    cheatTestSetRxRange(code_addr, 4);
    {
        Wire w2;
        wireStart(&w2, CHEAT_TEST_TITLE_A);
        const u32 data_block = wireBlock(&w2, 1, 1);
        wireInsn(&w2, data_block, insnStore(data_addr, 4, 0x0A0A0A0Au));
        const u32 code_block = wireBlock(&w2, 1, 1);
        wireInsn(&w2, code_block, insnStore(code_addr, 4, 0x0B0B0B0Bu));
        CHECK(uploadWire(&w2), "data + RX program installed for the debug check");
    }
    cheatTestSetDebugAttached(true);
    cheatTestLogClear();
    cheatTestClearEvents();
    cheatSrvWorkerStep();
    CHECK(cheatTestPeekU32(data_addr) == 0x0A0A0A0Au,
          "a data-only block keeps running while a debug session is attached");
    CHECK(cheatTestDebugWrites() == 1, "the data write used the debug handle (%u)",
          (unsigned)cheatTestDebugWrites());
    CHECK(cheatTestPeekU32(code_addr) == 0u, "the RX block was not executed while attached");
    CHECK(cheatTestPauses() == 0, "no dmnt Pause was attempted without dmnt");
    CHECK(cheatTestEventCount() == 1 &&
          cheatTestLastFault()->reason == NXUS_CHEAT_FAULT_CANNOT_FREEZE,
          "the skipped RX block reports CANNOT_FREEZE (%u)",
          (unsigned)cheatTestLastFault()->reason);
    CHECK(cheatTestLogContains("suspended"),
          "the suspension is logged once: \"%s\"", cheatTestLastLog());
    /* Repeated ticks do not spam the link with the same fault. */
    cheatSrvWorkerStep();
    CHECK(cheatTestEventCount() == 1, "the debug RX fault is sent once per attach");

    cheatTestSetDebugAttached(false);
    cheatTestLogClear();
    cheatSrvWorkerStep();
    CHECK(strstr(cheatTestLastLog(), "resumes") != NULL,
          "the resumption is logged once: \"%s\"", cheatTestLastLog());
    CHECK(cheatTestPeekU32(code_addr) == 0x0B0B0B0Bu,
          "the RX block runs again after the debug detach");
    CHECK(cheatTestPauses() == 1, "the RX block used a real dmnt Pause (%u)",
          (unsigned)cheatTestPauses());
    CHECK(cheatTestResumes() == 1, "and the matching Resume (%u)", (unsigned)cheatTestResumes());
}

/* ---- 12. patch-only upload (synchronous, non-resident) ------------------ */

static void testPatchOnlyUpload(void) {
    printf("[test] patch-only upload: runs at upload, journals, releases, stays non-resident\n");
    fresh();

    const u64 addr = CHEAT_TEST_BASE + 0xE00;
    const u32 original = 0x13572468u;
    cheatTestPoke(addr, &original, sizeof(original));

    Wire w;
    NxusCheatUploadReply reply;
    makeProgram(&w, CHEAT_TEST_TITLE_A, 0, 1, addr, 0x24681357u);
    const u32 writes = cheatTestWrites();
    CHECK(uploadWireReply(&w, &reply), "a patch-only program is accepted");
    CHECK(reply.accepted_blocks == 1 && reply.accepted_insns == 1 &&
          reply.rejected_reason == 0,
          "the reply counts the executed program (blocks=%u insns=%u reason=%u)",
          (unsigned)reply.accepted_blocks, (unsigned)reply.accepted_insns,
          (unsigned)reply.rejected_reason);
    CHECK(cheatTestPeekU32(addr) == 0x24681357u,
          "the patch was applied during the upload, not deferred to a tick");
    CHECK(cheatTestWrites() == writes + 1, "exactly one write was issued (%u)",
          (unsigned)(cheatTestWrites() - writes));

    {
        const NxusCheatStatus st = statusNow();
        CHECK(st.program_valid == 0 && st.block_count == 0 && st.insn_count == 0,
              "no program is resident after a patch-only upload (valid=%u blocks=%u insns=%u)",
              (unsigned)st.program_valid, (unsigned)st.block_count, (unsigned)st.insn_count);
        CHECK(st.journal_count == 1, "the write stays journalled for PanicOff (%u)",
              (unsigned)st.journal_count);
        CHECK(st.enabled_count == 0, "no resident block is enabled");
    }

    /* The worker has nothing to run: there is no resident program. */
    cheatSrvWorkerStep();
    CHECK(cheatTestWrites() == writes + 1, "a later tick does not repeat the patch");
    CHECK(statusNow().tick_count == 0, "no resident program means no ticks are counted");
    CHECK(g_Program.insns == NULL && g_PatchProgram.insns == NULL,
          "neither the resident slot nor the scratch slot owns an instruction array");

    /* A disabled patch block is a no-op: the upload-time enable flag is honoured. */
    {
        const u64 off_addr = CHEAT_TEST_BASE + 0xE04;
        Wire off;
        makeProgram(&off, CHEAT_TEST_TITLE_A, 0, 0, off_addr, 0x11112222u);
        CHECK(uploadWire(&off), "a disabled patch-only program is accepted");
        CHECK(cheatTestPeekU32(off_addr) == 0u, "a disabled patch block wrote nothing");
    }

    /* The patch-only write is reversible with no PC in the loop. */
    {
        NxusCheatRestore rs;
        nxusCheatSrvPanicOff(&rs);
        CHECK(rs.restored == 1 && rs.failed == 0,
              "PanicOff restored the patch-only write (%u restored, %u failed)",
              (unsigned)rs.restored, (unsigned)rs.failed);
        CHECK(cheatTestPeekU32(addr) == original, "the original value is back");
        CHECK(statusNow().journal_count == 0, "the journal is empty after the restore");
    }

    /* A patch-only upload must not displace - nor write back the patches of - a
     * resident program: g_Program keeps running and status keeps describing it. */
    fresh();
    {
        const u64 res_addr = CHEAT_TEST_BASE + 0xE40;
        const u64 one_shot = CHEAT_TEST_BASE + 0xE44;
        Wire res;
        makeProgram(&res, CHEAT_TEST_TITLE_A, 1, 1, res_addr, 0x0A0B0C0Du);
        CHECK(uploadWire(&res), "resident loop program installed");
        const NxusCheatStatus before = statusNow();
        CHECK(before.program_valid == 1 && before.block_count == 1,
              "the loop program is resident");

        Wire patch;
        makeProgram(&patch, CHEAT_TEST_TITLE_A, 0, 1, one_shot, 0x51515151u);
        CHECK(uploadWire(&patch), "a patch-only program is accepted next to the resident one");
        CHECK(cheatTestPeekU32(one_shot) == 0x51515151u, "the one-shot patch ran");
        {
            const NxusCheatStatus after = statusNow();
            CHECK(after.program_valid == 1 && after.block_count == 1 && after.insn_count == 1,
                  "the resident program is still the installed one (valid=%u blocks=%u insns=%u)",
                  (unsigned)after.program_valid, (unsigned)after.block_count,
                  (unsigned)after.insn_count);
            CHECK(after.tick_count == before.tick_count,
                  "the patch upload did not advance the worker's tick count");
        }
        cheatSrvWorkerStep();
        CHECK(cheatTestPeekU32(res_addr) == 0x0A0B0C0Du, "the resident loop still runs");
        CHECK(cheatTestPeekU32(one_shot) == 0x51515151u, "and the one-shot patch stays applied");
    }

    /* A loop-only program is resident with every block counted by status. */
    fresh();
    {
        Wire two;
        wireStart(&two, CHEAT_TEST_TITLE_A);
        wireInsn(&two, wireBlock(&two, 1, 1), insnStore(CHEAT_TEST_BASE + 0xE80, 4, 1));
        wireInsn(&two, wireBlock(&two, 1, 1), insnStore(CHEAT_TEST_BASE + 0xE84, 4, 2));
        CHECK(uploadWire(&two), "two-loop program installed");
        CHECK(statusNow().program_valid == 1 && statusNow().block_count == 2,
              "both loop blocks are resident (valid=%u blocks=%u)",
              (unsigned)statusNow().program_valid, (unsigned)statusNow().block_count);
        CHECK(statusNow().insn_count == 2, "and both instructions are counted (%u)",
              (unsigned)statusNow().insn_count);
    }
}

/* ---- 13. heap lifetime ------------------------------------------------- */

static void testHeapLifetime(void) {
    printf("[test] heap: patch uploads release, re-upload frees the old insns, clear/exit release\n");
    fresh();
    allocatorBegin();

    const u64 base = CHEAT_TEST_BASE + 0xF00;
    Wire w;

    /* Two patch-only uploads: each allocates its instruction array, runs, and
     * releases it before the upload returns, so the heap does not grow. */
    makeProgram(&w, CHEAT_TEST_TITLE_A, 0, 1, base, 0x01010101u);
    CHECK(uploadWire(&w), "first patch-only upload accepted");
    CHECK(cheatTestPeekU32(base) == 0x01010101u, "the first patch ran");
    CHECK(g_Allocs - g_Frees == 0, "the first patch upload released its array (live=%u)",
          (unsigned)(g_Allocs - g_Frees));

    makeProgram(&w, CHEAT_TEST_TITLE_A, 0, 1, base + 4u, 0x02020202u);
    CHECK(uploadWire(&w), "second patch-only upload accepted");
    CHECK(cheatTestPeekU32(base + 4u) == 0x02020202u, "the second patch ran too");
    CHECK(g_Allocs == 2 && g_Frees == 2,
          "two patch uploads => two allocations, two releases (%u/%u)",
          (unsigned)g_Allocs, (unsigned)g_Frees);
    CHECK(g_Allocs - g_Frees == 0, "repeated patch uploads do not grow the heap (live=%u)",
          (unsigned)(g_Allocs - g_Frees));

    /* A loop upload becomes resident and keeps exactly one array. */
    makeProgram(&w, CHEAT_TEST_TITLE_A, 1, 1, base + 8u, 0x03030303u);
    CHECK(uploadWire(&w), "loop program installed");
    CHECK(g_Allocs - g_Frees == 1, "exactly one instruction array is resident (live=%u)",
          (unsigned)(g_Allocs - g_Frees));
    CHECK(g_Program.insns != NULL && g_Program.insn_capacity == 1,
          "the resident program owns its one-instruction array");

    /* Re-upload: the OLD array must be freed (before this change it leaked). */
    {
        const void *old_insns = (const void *)g_Program.insns;
        makeProgram(&w, CHEAT_TEST_TITLE_A, 1, 1, base + 12u, 0x04040404u);
        CHECK(uploadWire(&w), "loop program re-uploaded");
        CHECK(freedContains(old_insns),
              "the previous instruction array was released (%u frees)",
              (unsigned)g_Frees);
        CHECK(g_Allocs - g_Frees == 1, "still exactly one array is resident (live=%u)",
              (unsigned)(g_Allocs - g_Frees));
    }

    /* Clear releases the resident array. */
    {
        const void *resident = (const void *)g_Program.insns;
        nxusCheatSrvClear();
        CHECK(g_Program.insns == NULL, "clear dropped the instruction pointer");
        CHECK(freedContains(resident), "clear released the resident instruction array");
        CHECK(g_Allocs - g_Frees == 0, "nothing is left allocated after clear (live=%u)",
              (unsigned)(g_Allocs - g_Frees));
    }

    /* Exit releases as well. */
    makeProgram(&w, CHEAT_TEST_TITLE_A, 1, 1, base + 16u, 0x05050505u);
    CHECK(uploadWire(&w), "loop program installed for the exit check");
    {
        const void *before_exit = (const void *)g_Program.insns;
        nxusCheatSrvExit();
        CHECK(g_Program.insns == NULL, "exit dropped the instruction pointer");
        CHECK(freedContains(before_exit), "exit released the resident instruction array");
        CHECK(g_Allocs - g_Frees == 0, "nothing is left allocated after exit (live=%u)",
              (unsigned)(g_Allocs - g_Frees));
    }

    allocatorEnd();
    nxusCheatSrvInit();          /* the following tests start from an initialised service */
}

/* ---- 14. failed uploads ------------------------------------------------- */

static void testUploadFailures(void) {
    printf("[test] upload failures: NO_MEMORY / rejected program keep the resident one\n");
    fresh();

    const u64 addr = CHEAT_TEST_BASE + 0x1000;
    Wire w;
    NxusCheatUploadReply reply;
    makeProgram(&w, CHEAT_TEST_TITLE_A, 1, 1, addr, 0xAAAA0001u);
    CHECK(uploadWire(&w), "resident loop program installed");
    cheatSrvWorkerStep();
    CHECK(cheatTestPeekU32(addr) == 0xAAAA0001u, "the resident program runs");

    const void *resident = (const void *)g_Program.insns;

    /* Allocation failure (NXUS_CHEATVM_ERR_NO_MEMORY, wire code 9): the installed
     * program and its instruction array must survive untouched. */
    nxusCheatSetAllocator(failAlloc, testFree, NULL);
    {
        Wire big;
        makeProgram(&big, CHEAT_TEST_TITLE_A, 1, 1, addr, 0xBBBB0002u);
        CHECK(!uploadWireReply(&big, &reply), "an upload that cannot allocate is refused");
        CHECK(reply.rejected_reason == (u32)(-NXUS_CHEATVM_ERR_NO_MEMORY),
              "the reason is NO_MEMORY (%u)", (unsigned)reply.rejected_reason);
        CHECK(g_Program.insns == resident && statusNow().program_valid == 1,
              "the installed program still owns its instruction array");
        CHECK(statusNow().block_count == 1,
              "status still describes the installed program (%u block(s))",
              (unsigned)statusNow().block_count);
    }

    /* ...and it still executes (the probe/apply pass sees a differing value). */
    {
        const u32 moved = 0u;
        cheatTestPoke(addr, &moved, sizeof(moved));
        cheatSrvWorkerStep();
        CHECK(cheatTestPeekU32(addr) == 0xAAAA0001u,
              "the old program still runs after a failed replacement");
    }

    /* A patch-only upload that cannot allocate executes nothing at all. */
    {
        const u64 patch_addr = CHEAT_TEST_BASE + 0x1004;
        Wire patch;
        makeProgram(&patch, CHEAT_TEST_TITLE_A, 0, 1, patch_addr, 0xCCCC0003u);
        CHECK(!uploadWireReply(&patch, &reply), "a patch-only upload that cannot allocate fails");
        CHECK(cheatTestPeekU32(patch_addr) == 0u, "and executed nothing");
        CHECK(g_Program.insns == resident, "the resident program was not touched");
    }
    allocatorEnd();

    /* A program rejected by validation leaves the installed program untouched too
     * (install validates before it allocates or writes). */
    makeProgram(&w, CHEAT_TEST_TITLE_A, 1, 1, addr, 0xDDDD0004u);
    w.insns[0].op = 999u;        /* no such opcode */
    CHECK(!uploadWireReply(&w, &reply), "an invalid program is refused");
    CHECK(reply.rejected_reason == 3u,
          "the reason is the interpreter's bad-block code (%u)", (unsigned)reply.rejected_reason);
    CHECK(g_Program.insns == resident && statusNow().program_valid == 1,
          "the installed program survived the refused replacement");
    cheatSrvWorkerStep();
    CHECK(cheatTestPeekU32(addr) == 0xAAAA0001u, "and it keeps running");
}

/* ---- 15. journal full --------------------------------------------------- */

/*
 * The reported bug: the restore journal was a fixed 512-entry array, so after 512
 * distinct addresses every further write was refused - and because a restore kept
 * the journal, the console stayed unable to apply ANY cheat until it was rebooted.
 * The journal now grows (up to 16384 entries) and a restore frees what it wrote
 * back (see test_cheatvm.c for the grow/compaction/restore unit tests).  What is
 * left is the CEILING, and this test drives it through the shipped service:
 *
 *   - the worker disables the block immediately and reports JOURNAL_FULL,
 *   - the refused write never reaches the target,
 *   - a patch-only upload reports the positive code 10 (the server maps that to
 *     NXUS_ERR_BAD_STATE + NXUS_REASON_JOURNAL_FULL instead of reason=9).
 */
static void testJournalFull(void) {
    const u64 addr = CHEAT_TEST_BASE + 0x20000u;
    Wire w;
    NxusCheatUploadReply reply;
    CheatIoState state;
    NxusCheatIo io;
    u32 i;
    bool all_ok;

    printf("[test] journal full: block disabled, nothing written, reason 10 on upload\n");
    fresh();

    /* The resident program is installed FIRST: a loop upload would restore (and
     * therefore empty) the previous journal before taking over. */
    makeProgram(&w, CHEAT_TEST_TITLE_A, 1, 1, addr, 0xDEADBEEFu);
    CHECK(uploadWire(&w), "the loop program installs before the journal is filled");

    /* Fill the real journal to its ceiling through the service's own IO adapter. */
    cheatIoInit(&state, &io, false);
    all_ok = true;
    for (i = 0; i < NXUS_CHEATVM_MAX_JOURNAL; i++) {
        if (nxusCheatJournalRemember(&g_Journal, &io, CHEAT_TEST_BASE + (u64)i * 4u, 4, 0) != 0) {
            all_ok = false;
            break;
        }
    }
    CHECK(all_ok, "the real journal fills to its 16384-entry ceiling (%u)",
          (unsigned)g_Journal.count);
    CHECK(g_Journal.count == NXUS_CHEATVM_MAX_JOURNAL &&
          g_Journal.capacity == NXUS_CHEATVM_MAX_JOURNAL,
          "the journal is exactly at its ceiling (count=%u cap=%u)",
          (unsigned)g_Journal.count, (unsigned)g_Journal.capacity);

    cheatSrvWorkerStep();
    CHECK(statusNow().last_error == (u32)NXUS_CHEATVM_ERR_JOURNAL_FULL,
          "the worker records ERR_JOURNAL_FULL (%u)", (unsigned)statusNow().last_error);
    CHECK(statusNow().enabled_count == 0, "the block is disabled immediately");
    CHECK(cheatTestEventCount() == 1 &&
          cheatTestLastFault()->reason == NXUS_CHEAT_FAULT_JOURNAL_FULL,
          "the fault event says JOURNAL_FULL (%u)", (unsigned)cheatTestLastFault()->reason);
    CHECK(cheatTestWrites() == 0, "the refused write never reached the target (%u writes)",
          (unsigned)cheatTestWrites());
    CHECK(cheatTestPeekU32(addr) == 0u, "the target is untouched");

    /* A patch-only upload is refused with the positive code 10. */
    fresh();
    cheatIoInit(&state, &io, false);
    all_ok = true;
    for (i = 0; i < NXUS_CHEATVM_MAX_JOURNAL; i++) {
        if (nxusCheatJournalRemember(&g_Journal, &io, CHEAT_TEST_BASE + (u64)i * 4u, 4, 0) != 0) {
            all_ok = false;
            break;
        }
    }
    CHECK(all_ok, "the journal is filled again for the upload check");

    makeProgram(&w, CHEAT_TEST_TITLE_A, 0, 1, addr, 0x11223344u);
    CHECK(!uploadWireReply(&w, &reply), "a patch-only upload that would overflow is refused");
    CHECK(reply.rejected_reason == (u32)(-NXUS_CHEATVM_ERR_JOURNAL_FULL),
          "rejected_reason is the positive JOURNAL_FULL code (%u)",
          (unsigned)reply.rejected_reason);
    CHECK(reply.rejected_reason == 10u, "the wire code is 10 (%u)",
          (unsigned)reply.rejected_reason);
    CHECK(cheatTestPeekU32(addr) == 0u, "the refused patch wrote nothing");
    CHECK(cheatTestWrites() == 0, "no dmnt write was issued (%u)", (unsigned)cheatTestWrites());

    /* The reason the server appends is distinct from every existing one. */
    CHECK(NXUS_REASON_JOURNAL_FULL == 14u, "NXUS_REASON_JOURNAL_FULL is the appended code 14");
    CHECK(NXUS_REASON_JOURNAL_FULL != NXUS_REASON_DEBUG_LOCKED &&
          NXUS_REASON_JOURNAL_FULL != NXUS_REASON_SLOT_FULL &&
          NXUS_REASON_JOURNAL_FULL != NXUS_REASON_RETRY_LATER &&
          NXUS_REASON_JOURNAL_FULL != NXUS_REASON_BAD_ARG,
          "it does not collide with an existing reason");
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
    testFreeze();
    testLifecycle();
    testPatchOnlyUpload();
    testHeapLifetime();
    testUploadFailures();
    testJournalFull();

    nxusCheatSrvExit();
    printf("\n%d checks, %d failure(s)\n", g_checks, g_failures);
    if (g_failures != 0) {
        printf("CHEAT SERVICE TESTS FAILED\n");
        return 1;
    }
    printf("ALL CHEAT SERVICE TESTS PASSED\n");
    return 0;
}
