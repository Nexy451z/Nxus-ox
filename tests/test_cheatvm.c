/* コンソール側チート VM (core/nxus_cheatvm.c) のホストテスト。
 *
 * なぜモック IO か: 実機の dmnt:cht を挟まずに「どのアドレスへ何バイト、
 * どの値で書いたか」を厳密に観測するため。失敗注入もここで行う。
 * メモリは 64 KiB の配列で、アドレス = 配列の添字（領域ベースは PC が解決して
 * 送る契約なので、テストも最終アドレスを直接使う）。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nxus_cheatvm.h"

#define MOCK_MEM_SIZE 0x10000u
#define MOCK_MAX_WRITES 2048u

static int g_checks = 0;
static int g_failures = 0;

#define CHECK(cond, what)                                                         \
    do {                                                                          \
        g_checks++;                                                               \
        if (!(cond)) {                                                            \
            g_failures++;                                                         \
            printf("  FAIL  %s (line %d)\n", (what), __LINE__);                   \
        }                                                                         \
    } while (0)

/* ======================================================================== */
/* モック IO                                                                */
/* ======================================================================== */

static u8 g_mem[MOCK_MEM_SIZE];

typedef struct MockWrite {
    u64 address;
    u32 size;
    u8 data[8];
    bool allow_rx;
} MockWrite;

static MockWrite g_write_log[MOCK_MAX_WRITES];
static u32 g_write_log_count;

static bool g_fail_read_on;
static u64 g_fail_read_address;
static bool g_fail_write_on;
static u64 g_fail_write_address;

static int mock_read(void *user, u64 address, void *out, u32 size) {
    (void)user;
    if (size == 0 || size > 8) return -1;
    if (address >= MOCK_MEM_SIZE || (u64)size > (u64)MOCK_MEM_SIZE - address) return -1;
    if (g_fail_read_on && address == g_fail_read_address) return -1;
    memcpy(out, g_mem + address, size);
    return 0;
}

static int mock_write(void *user, u64 address, const void *data, u32 size, bool allow_rx) {
    (void)user;
    if (size == 0 || size > 8) return -1;
    if (address >= MOCK_MEM_SIZE || (u64)size > (u64)MOCK_MEM_SIZE - address) return -1;
    if (g_fail_write_on && address == g_fail_write_address) return -1;
    if (g_write_log_count < MOCK_MAX_WRITES) {
        MockWrite *entry = &g_write_log[g_write_log_count];
        entry->address = address;
        entry->size = size;
        memset(entry->data, 0, sizeof entry->data);
        memcpy(entry->data, data, size);
        entry->allow_rx = allow_rx;
        g_write_log_count++;
    }
    memcpy(g_mem + address, data, size);
    return 0;
}

static const NxusCheatIo g_io = { NULL, mock_read, mock_write };

/* 書き込みジャーナルはテスト全体で 1 本（RunBlock が使う実体でもある）。 */
static NxusCheatJournal g_journal;

static void mock_reset(void) {
    memset(g_mem, 0, sizeof g_mem);
    g_write_log_count = 0;
    g_fail_read_on = false;
    g_fail_write_on = false;
    g_fail_read_address = 0;
    g_fail_write_address = 0;
    nxusCheatJournalReset(&g_journal);
}

static void mem_put(u64 address, u64 value, u32 width) {
    u8 bytes[8];
    u32 index;
    if (address >= MOCK_MEM_SIZE || width > 8) return;
    for (index = 0; index < width; index++) bytes[index] = (u8)(value >> (8u * index));
    memcpy(g_mem + address, bytes, width);
}

static u64 mem_get(u64 address, u32 width) {
    u64 value = 0;
    u32 index;
    if (address >= MOCK_MEM_SIZE) return 0;
    for (index = 0; index < width; index++) value |= (u64)g_mem[address + index] << (8u * index);
    return value;
}

static u32 writes_at(u64 address, u32 width) {
    u32 index;
    u32 count = 0;
    for (index = 0; index < g_write_log_count; index++) {
        if (g_write_log[index].address == address && g_write_log[index].size == width) count++;
    }
    return count;
}

static u64 last_write_value(u64 address, u32 width) {
    u32 index;
    for (index = g_write_log_count; index > 0; index--) {
        const MockWrite *entry = &g_write_log[index - 1];
        if (entry->address == address && entry->size == width) {
            u64 value = 0;
            u32 byte;
            for (byte = 0; byte < width; byte++) value |= (u64)entry->data[byte] << (8u * byte);
            return value;
        }
    }
    return 0;
}

static bool all_writes_allow_rx(void) {
    u32 index;
    if (g_write_log_count == 0) return false;
    for (index = 0; index < g_write_log_count; index++) {
        if (!g_write_log[index].allow_rx) return false;
    }
    return true;
}

/* ======================================================================== */
/* wire プログラムビルダ                                                */
/* ======================================================================== */

static u8 g_wire[16384];
static u32 g_wire_blocks;
static u32 g_wire_insns;

static size_t wire_blocks_off(void) {
    return sizeof(NxusCheatProgramHeader);
}

static size_t wire_insns_off(void) {
    return wire_blocks_off() + (size_t)g_wire_blocks * sizeof(NxusCheatBlockDesc);
}

static size_t wire_length(void) {
    return wire_insns_off() + (size_t)g_wire_insns * sizeof(NxusCheatInsn);
}

static NxusCheatProgramHeader *wire_header(void) {
    return (NxusCheatProgramHeader *)g_wire;
}

static NxusCheatBlockDesc *wire_block(u32 index) {
    return (NxusCheatBlockDesc *)(g_wire + wire_blocks_off() +
                                  (size_t)index * sizeof(NxusCheatBlockDesc));
}

static NxusCheatInsn *wire_insn(u32 index) {
    return (NxusCheatInsn *)(g_wire + wire_insns_off() +
                             (size_t)index * sizeof(NxusCheatInsn));
}

static void wire_begin(u32 blocks, u32 insns) {
    memset(g_wire, 0, sizeof g_wire);
    g_wire_blocks = blocks;
    g_wire_insns = insns;
    wire_header()->magic = NXUS_CHEATVM_MAGIC;
    wire_header()->version = NXUS_CHEATVM_VERSION;
    wire_header()->build_id = 0x1122334455667788ull;
    wire_header()->program_id = 0x0100C3800049C000ull;
    wire_header()->block_count = blocks;
    wire_header()->insn_count = insns;
    wire_header()->total_bytes = (u32)wire_length();
}

static void wire_block_set(u32 index, u32 mode, u32 first, u32 count, u32 enabled) {
    NxusCheatBlockDesc *block = wire_block(index);
    block->index = index;
    block->mode = mode;
    block->first = first;
    block->count = count;
    block->enabled = enabled;
    block->reserved = 0;
}

static void wire_insn_set(u32 index, u32 op, u32 width, u32 region, u32 cmp, u32 reg_a,
                          u32 reg_b, u32 flags, u32 target, u32 address, u64 value) {
    NxusCheatInsn *insn = wire_insn(index);
    insn->op = (u16)op;
    insn->width = (u8)width;
    insn->region = (u8)region;
    insn->cmp = (u8)cmp;
    insn->reg_a = (u8)reg_a;
    insn->reg_b = (u8)reg_b;
    insn->flags = (u8)flags;
    insn->target = target;
    insn->address = address;
    insn->value = value;
}

static void build_minimal_program(void) {
    wire_begin(1, 1);
    wire_block_set(0, 1, 0, 1, 0);
    wire_insn_set(0, NxusCheatOp_Nop, 0, 0, 0, 0, 0, 0, 0, 0, 0);
}

/* ======================================================================== */
/* install の検証                                                          */
/* ======================================================================== */

static void test_install_validation(void) {
    NxusCheatProgram program;
    NxusCheatProgram guard;

    printf("- install validation\n");
    mock_reset();
    nxusCheatProgramInit(&program);

    build_minimal_program();
    CHECK(nxusCheatInstall(&program, g_wire, wire_length()) == 0, "a well-formed program installs");
    CHECK(program.header.block_count == 1 && program.header.insn_count == 1,
          "installed block/insn counts");
    CHECK(program.state[0].enabled == false, "wire enabled=0 leaves the block disabled");

    /* 失敗時に program が変わらないことを見るための番犬。 */
    memset(&guard, 0, sizeof guard);
    guard.header.magic = 0xDEADBEEFu;
    guard.header.block_count = 7;

    build_minimal_program();
    wire_header()->magic = NXUS_CHEATVM_MAGIC ^ 1u;
    CHECK(nxusCheatInstall(&guard, g_wire, wire_length()) == -1, "bad magic -> -1");
    CHECK(guard.header.magic == 0xDEADBEEFu, "a failed install does not touch the program");

    build_minimal_program();
    wire_header()->version = NXUS_CHEATVM_VERSION + 1u;
    CHECK(nxusCheatInstall(&guard, g_wire, wire_length()) == -1, "bad version -> -1");

    build_minimal_program();
    wire_header()->total_bytes += 8u;
    CHECK(nxusCheatInstall(&guard, g_wire, wire_length()) == -2, "total_bytes mismatch -> -2");
    CHECK(guard.header.block_count == 7, "still untouched after a size failure");

    build_minimal_program();
    CHECK(nxusCheatInstall(&guard, g_wire, wire_length() - 4u) == -2, "short wire payload -> -2");

    build_minimal_program();
    wire_header()->insn_count = NXUS_CHEATVM_MAX_INSNS + 1u;
    CHECK(nxusCheatInstall(&guard, g_wire, wire_length()) == -5, "too many instructions -> -5");

    build_minimal_program();
    wire_header()->block_count = NXUS_CHEATVM_MAX_BLOCKS + 1u;
    CHECK(nxusCheatInstall(&guard, g_wire, wire_length()) == -3, "too many blocks -> -3");

    build_minimal_program();
    wire_block_set(0, 1, 1, 1, 0); /* first + count = 2 > insn_count = 1 */
    CHECK(nxusCheatInstall(&guard, g_wire, wire_length()) == -3, "block range past insn_count -> -3");

    build_minimal_program();
    wire_block_set(0, 2, 0, 1, 0); /* mode は 0/1 だけ */
    CHECK(nxusCheatInstall(&guard, g_wire, wire_length()) == -3, "mode 2 -> -3");

    build_minimal_program();
    wire_insn_set(0, 23, 0, 0, 0, 0, 0, 0, 0, 0, 0); /* NxusCheatOp_KeypressConditional より上 */
    CHECK(nxusCheatInstall(&guard, g_wire, wire_length()) == -3, "unsupported opcode -> -3");

    build_minimal_program();
    wire_insn_set(0, NxusCheatOp_StoreStatic, 3, 0, 0, 0, 0, 0, 0, 0x40, 1);
    CHECK(nxusCheatInstall(&guard, g_wire, wire_length()) == -3, "width 3 -> -3");

    build_minimal_program();
    wire_insn_set(0, NxusCheatOp_StoreStatic, 4, 5, 0, 0, 0, 0, 0, 0x40, 1);
    CHECK(nxusCheatInstall(&guard, g_wire, wire_length()) == -3, "region 5 -> -3");

    /* 分岐先がブロックの外（前半・後半の両方）。 */
    wire_begin(1, 2);
    wire_block_set(0, 1, 0, 2, 0);
    wire_insn_set(0, NxusCheatOp_Else, 0, 0, 0, 0, 0, 0, 2, 0, 0);
    wire_insn_set(1, NxusCheatOp_Nop, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    CHECK(nxusCheatInstall(&guard, g_wire, wire_length()) == -4, "target at block end -> -4");

    wire_begin(1, 3);
    wire_block_set(0, 1, 1, 2, 0);
    wire_insn_set(0, NxusCheatOp_Nop, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    wire_insn_set(1, NxusCheatOp_KeypressConditional, 0, 0, 0, 0, 0, 0, 0, 0, 1);
    wire_insn_set(2, NxusCheatOp_EndConditional, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    CHECK(nxusCheatInstall(&guard, g_wire, wire_length()) == -4, "target before block start -> -4");

    /* 壊れた wire を入れても、直前の正常な program はそのまま使える。 */
    build_minimal_program();
    CHECK(nxusCheatInstall(&program, g_wire, wire_length()) == 0, "reinstall after failures still works");
    CHECK(nxusCheatRunBlock(&program, 3, &g_io, 0, &g_journal) == NXUS_CHEATVM_ERR_BAD_BLOCK,
          "RunBlock rejects an index outside the program");
    nxusCheatReset(&program);
    CHECK(nxusCheatTick(&program, &g_io, 0, &g_journal) == 0, "tick with an empty program runs nothing");
    nxusCheatProgramRelease(&program);
}

/* ======================================================================== */
/* StoreStatic: 幅と領域                                                    */
/* ======================================================================== */

static void test_store_static_widths_and_regions(void) {
    NxusCheatProgram program;

    printf("- StoreStatic: widths, truncation, regions\n");
    mock_reset();
    nxusCheatProgramInit(&program);

    wire_begin(1, 7);
    wire_block_set(0, 1, 0, 7, 1);
    wire_insn_set(0, NxusCheatOp_StoreStatic, 1, NxusCheatRegion_Absolute, 0, 0, 0, 0, 0, 0x0100, 0xAB);
    wire_insn_set(1, NxusCheatOp_StoreStatic, 2, NxusCheatRegion_Absolute, 0, 0, 0, 0, 0, 0x0104, 0xBEEF);
    wire_insn_set(2, NxusCheatOp_StoreStatic, 4, NxusCheatRegion_Absolute, 0, 0, 0, 0, 0, 0x0108, 0xDEADBEEFull);
    wire_insn_set(3, NxusCheatOp_StoreStatic, 8, NxusCheatRegion_Absolute, 0, 0, 0, 0, 0, 0x0110,
                  0x1122334455667788ull);
    wire_insn_set(4, NxusCheatOp_StoreStatic, 4, NxusCheatRegion_Main, 0, 0, 0, 0, 0, 0x0200, 0xCAFEBABEull);
    wire_insn_set(5, NxusCheatOp_StoreStatic, 4, NxusCheatRegion_Aslr, 0, 0, 0, 0, 0, 0x0204, 0x01020304ull);
    wire_insn_set(6, NxusCheatOp_StoreStatic, 1, NxusCheatRegion_Absolute, 0, 0, 0, 0, 0, 0x0300, 0x1FFull);
    CHECK(nxusCheatInstall(&program, g_wire, wire_length()) == 0, "store program installs");

    CHECK(nxusCheatTick(&program, &g_io, 0, &g_journal) == 1, "one loop block ran");
    CHECK(mem_get(0x0100, 1) == 0xAB, "width 1 write");
    CHECK(mem_get(0x0104, 2) == 0xBEEF, "width 2 write");
    CHECK(mem_get(0x0108, 4) == 0xDEADBEEFull, "width 4 write");
    CHECK(mem_get(0x0110, 8) == 0x1122334455667788ull, "width 8 write");
    CHECK(mem_get(0x0200, 4) == 0xCAFEBABEull, "Main region resolves to the uploaded address");
    CHECK(mem_get(0x0204, 4) == 0x01020304ull, "Aslr region resolves the same way");
    CHECK(mem_get(0x0300, 1) == 0xFF, "width 1 truncates the value to 8 bits");
    CHECK(writes_at(0x0108, 4) == 1 && g_write_log_count == 7, "one write per instruction");
    CHECK(all_writes_allow_rx(), "every write carries allow_rx");
    CHECK(last_write_value(0x0110, 8) == 0x1122334455667788ull, "write log records the little-endian value");
    nxusCheatProgramRelease(&program);
}

/* ======================================================================== */
/* 条件分岐（真・偽・Else）                                                  */
/* ======================================================================== */

static void test_conditional_and_else(void) {
    NxusCheatProgram program;

    printf("- conditionals: true / false / else\n");
    mock_reset();
    nxusCheatProgramInit(&program);

    /* 0: if [0x2600] == 7 -> else へ (target=3)
       1: [0x2610] = 0xAA
       2: else -> 4 (EndConditional の次)
       3: [0x2610] = 0xBB
       4: end                                                */
    wire_begin(1, 5);
    wire_block_set(0, 1, 0, 5, 1);
    wire_insn_set(0, NxusCheatOp_BeginConditional, 4, NxusCheatRegion_Absolute,
                  NxusCheatCmp_Equal, 0, 0, 0, 3, 0x2600, 7);
    wire_insn_set(1, NxusCheatOp_StoreStatic, 4, NxusCheatRegion_Absolute, 0, 0, 0, 0, 0, 0x2610, 0xAAull);
    wire_insn_set(2, NxusCheatOp_Else, 0, 0, 0, 0, 0, 0, 4, 0, 0);
    wire_insn_set(3, NxusCheatOp_StoreStatic, 4, NxusCheatRegion_Absolute, 0, 0, 0, 0, 0, 0x2610, 0xBBull);
    wire_insn_set(4, NxusCheatOp_EndConditional, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    CHECK(nxusCheatInstall(&program, g_wire, wire_length()) == 0, "conditional program installs");

    mem_put(0x2600, 7, 4);
    CHECK(nxusCheatTick(&program, &g_io, 0, &g_journal) == 1, "conditional block ran");
    CHECK(last_write_value(0x2610, 4) == 0xAAull, "true branch runs the then-body");
    CHECK(writes_at(0x2610, 4) == 1, "the else body is skipped when true");

    mock_reset();
    nxusCheatReset(&program);
    CHECK(nxusCheatInstall(&program, g_wire, wire_length()) == 0, "reinstall before the false case");
    mem_put(0x2600, 8, 4);
    (void)nxusCheatTick(&program, &g_io, 0, &g_journal);
    CHECK(last_write_value(0x2610, 4) == 0xBBull, "false condition takes the else body");
    CHECK(writes_at(0x2610, 4) == 1, "only one of the two bodies runs");

    /* Else を持たない形 (EndConditional は素通り)。 */
    mock_reset();
    nxusCheatReset(&program);
    wire_begin(1, 3);
    wire_block_set(0, 1, 0, 3, 1);
    wire_insn_set(0, NxusCheatOp_BeginConditional, 4, NxusCheatRegion_Absolute, NxusCheatCmp_Equal,
                  0, 0, 0, 2, 0x2620, 1);
    wire_insn_set(1, NxusCheatOp_StoreStatic, 4, NxusCheatRegion_Absolute, 0, 0, 0, 0, 0, 0x2630, 0x77ull);
    wire_insn_set(2, NxusCheatOp_EndConditional, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    CHECK(nxusCheatInstall(&program, g_wire, wire_length()) == 0, "conditional without else installs");
    mem_put(0x2620, 1, 4);
    (void)nxusCheatTick(&program, &g_io, 0, &g_journal);
    CHECK(writes_at(0x2630, 4) == 1, "condition true falls through EndConditional");
    nxusCheatProgramRelease(&program);
}

/* ======================================================================== */
/* ループ                                                                   */
/* ======================================================================== */

static void test_loop(void) {
    NxusCheatProgram program;

    printf("- loops\n");
    mock_reset();
    nxusCheatProgramInit(&program);

    /* 0: r2 = 3
       1: [0x2300] = 0x77
       2: loop end -> 0 (r2 が残っていれば 1 へ戻る)                */
    wire_begin(1, 3);
    wire_block_set(0, 1, 0, 3, 1);
    wire_insn_set(0, NxusCheatOp_LoopStart, 0, 0, 0, 2, 0, 0, 1, 0, 3);
    wire_insn_set(1, NxusCheatOp_StoreStatic, 4, NxusCheatRegion_Absolute, 0, 0, 0, 0, 0, 0x2300, 0x77ull);
    wire_insn_set(2, NxusCheatOp_LoopEnd, 0, 0, 0, 2, 0, 0, 0, 0, 0);
    CHECK(nxusCheatInstall(&program, g_wire, wire_length()) == 0, "loop program installs");
    CHECK(nxusCheatTick(&program, &g_io, 0, &g_journal) == 1, "loop block ran");
    CHECK(writes_at(0x2300, 4) == 3, "the body ran exactly three times");
    CHECK(program.registers[2] == 0, "the counter register ends at zero");
    CHECK(program.state[0].last_error == 0, "the loop reports no error");

    /* 0 回ループ: 本体を丸ごと飛ばす（Atmosphere のアンダーフロー回避）。 */
    mock_reset();
    nxusCheatReset(&program);
    wire_begin(1, 3);
    wire_block_set(0, 1, 0, 3, 1);
    wire_insn_set(0, NxusCheatOp_LoopStart, 0, 0, 0, 1, 0, 0, 1, 0, 0);
    wire_insn_set(1, NxusCheatOp_StoreStatic, 4, NxusCheatRegion_Absolute, 0, 0, 0, 0, 0, 0x2310, 0x55ull);
    wire_insn_set(2, NxusCheatOp_LoopEnd, 0, 0, 0, 1, 0, 0, 0, 0, 0);
    CHECK(nxusCheatInstall(&program, g_wire, wire_length()) == 0, "zero-iteration loop installs");
    (void)nxusCheatTick(&program, &g_io, 0, &g_journal);
    CHECK(writes_at(0x2310, 4) == 0, "a zero-iteration loop skips its body");
    nxusCheatProgramRelease(&program);
}

/* ======================================================================== */
/* キー条件                                                                 */
/* ======================================================================== */

static void test_keypress_conditional(void) {
    NxusCheatProgram program;

    printf("- keypress conditional (all bits AND)\n");
    mock_reset();
    nxusCheatProgramInit(&program);

    wire_begin(1, 3);
    wire_block_set(0, 1, 0, 3, 1);
    wire_insn_set(0, NxusCheatOp_KeypressConditional, 0, 0, 0, 0, 0, 0, 2, 0, 0x3);
    wire_insn_set(1, NxusCheatOp_StoreStatic, 4, NxusCheatRegion_Absolute, 0, 0, 0, 0, 0, 0x2700, 0x99ull);
    wire_insn_set(2, NxusCheatOp_EndConditional, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    CHECK(nxusCheatInstall(&program, g_wire, wire_length()) == 0, "key program installs");

    (void)nxusCheatTick(&program, &g_io, 0x3, &g_journal);
    CHECK(writes_at(0x2700, 4) == 1, "every mask bit held -> body runs");

    (void)nxusCheatTick(&program, &g_io, 0x1, &g_journal);
    CHECK(writes_at(0x2700, 4) == 1, "a missing bit blocks the body");

    (void)nxusCheatTick(&program, &g_io, 0xFFFFFFFFull, &g_journal);
    CHECK(writes_at(0x2700, 4) == 2, "extra held bits do not matter");

    (void)nxusCheatTick(&program, &g_io, 0x2, &g_journal);
    CHECK(writes_at(0x2700, 4) == 2, "another partial mask also blocks");
    nxusCheatProgramRelease(&program);
}

/* ======================================================================== */
/* レジスタ演算                                                             */
/* ======================================================================== */

static void test_register_operations(void) {
    NxusCheatProgram program;

    printf("- register operations\n");
    mock_reset();
    nxusCheatProgramInit(&program);

    /* 0:  r1 = 0x1000
       1:  r1 = r1 + 0x20 = 0x1020
       2:  r1 = r1 - 0x20 = 0x1000
       3:  r1 = r1 * 2 = 0x2000
       4:  r1 = r1 >> 4 = 0x200
       5:  r3 = 0xFF
       6:  r3 = r3 + 0x10 -> 0x0F (幅 1 に丸め)
       7:  r4 = [0x1010] (LoadRegMem)
       8:  r5 = [r1 + 0x10] (LoadRegMem, flags=1)
       9:  r1 = 0x3000
       10: r6 = 0x20
       11: [r1 + r6] = 0x5A5A5A5A, r1 += 4 (StoreStaticToReg, flags=3)
       12: r7 = 0x3004
       13: r7 = [r7] (LoadRegMemReg)
       14: r9 = 8
       15: r8 = [r8 + r9] (LoadRegMemRegReg)
       16: r10 = 0x3200
       17: r11 = 0xABCD
       18: [r10] = r11 (StoreReg, width 2)
       19: r12 = 0x55
       20: save r12
       21: r12 = 0x66
       22: restore r12
       23: nop                                                             */
    wire_begin(1, 24);
    wire_block_set(0, 1, 0, 24, 1);
    wire_insn_set(0, NxusCheatOp_LoadRegImm, 0, 0, 0, 1, 0, 0, 0, 0, 0x1000);
    wire_insn_set(1, NxusCheatOp_ArithImm, 4, 0, NxusCheatArith_Add, 1, 0, 0, 0, 0, 0x20);
    wire_insn_set(2, NxusCheatOp_ArithImm, 4, 0, NxusCheatArith_Sub, 1, 0, 0, 0, 0, 0x20);
    wire_insn_set(3, NxusCheatOp_ArithImm, 4, 0, NxusCheatArith_Mul, 1, 0, 0, 0, 0, 2);
    wire_insn_set(4, NxusCheatOp_ArithImm, 4, 0, NxusCheatArith_Rsh, 1, 0, 0, 0, 0, 4);
    wire_insn_set(5, NxusCheatOp_LoadRegImm, 0, 0, 0, 3, 0, 0, 0, 0, 0xFF);
    wire_insn_set(6, NxusCheatOp_ArithImm, 1, 0, NxusCheatArith_Add, 3, 0, 0, 0, 0, 0x10);
    wire_insn_set(7, NxusCheatOp_LoadRegMem, 4, NxusCheatRegion_Absolute, 0, 4, 0, 0, 0, 0x1010, 0);
    wire_insn_set(8, NxusCheatOp_LoadRegMem, 4, NxusCheatRegion_Absolute, 0, 5, 1, 1, 0, 0x10, 0);
    wire_insn_set(9, NxusCheatOp_LoadRegImm, 0, 0, 0, 1, 0, 0, 0, 0, 0x3000);
    wire_insn_set(10, NxusCheatOp_LoadRegImm, 0, 0, 0, 6, 0, 0, 0, 0, 0x20);
    wire_insn_set(11, NxusCheatOp_StoreStaticToReg, 4, 0, 0, 1, 6, 3, 0, 0, 0x5A5A5A5Aull);
    wire_insn_set(12, NxusCheatOp_LoadRegImm, 0, 0, 0, 7, 0, 0, 0, 0, 0x3004);
    wire_insn_set(13, NxusCheatOp_LoadRegMemReg, 4, 0, 0, 7, 0, 0, 0, 0, 0);
    wire_insn_set(14, NxusCheatOp_LoadRegImm, 0, 0, 0, 8, 0, 0, 0, 0, 0x3100);
    wire_insn_set(15, NxusCheatOp_LoadRegImm, 0, 0, 0, 9, 0, 0, 0, 0, 8);
    wire_insn_set(16, NxusCheatOp_LoadRegMemRegReg, 4, 0, 0, 8, 9, 0, 0, 0, 0);
    wire_insn_set(17, NxusCheatOp_LoadRegImm, 0, 0, 0, 10, 0, 0, 0, 0, 0x3200);
    wire_insn_set(18, NxusCheatOp_LoadRegImm, 0, 0, 0, 11, 0, 0, 0, 0, 0xABCD);
    wire_insn_set(19, NxusCheatOp_StoreReg, 2, 0, 0, 10, 11, 0, 0, 0, 0);
    wire_insn_set(20, NxusCheatOp_LoadRegImm, 0, 0, 0, 12, 0, 0, 0, 0, 0x55);
    wire_insn_set(21, NxusCheatOp_SaveRegs, 0, 0, 0, 0, 0, 0, 0, 0, 1u << 12);
    wire_insn_set(22, NxusCheatOp_LoadRegImm, 0, 0, 0, 12, 0, 0, 0, 0, 0x66);
    wire_insn_set(23, NxusCheatOp_RestoreRegs, 0, 0, 0, 0, 0, 0, 0, 0, 1u << 12);

    mem_put(0x1010, 0xCAFEBABEull, 4);
    mem_put(0x210, 0x12345678ull, 4);
    mem_put(0x3004, 0x0000BEEFull, 4);
    mem_put(0x3108, 0x77777777ull, 4);

    CHECK(nxusCheatInstall(&program, g_wire, wire_length()) == 0, "register program installs");
    CHECK(nxusCheatRunBlock(&program, 0, &g_io, 0, &g_journal) == NXUS_CHEATVM_OK, "register program runs");

    CHECK(program.registers[3] == 0x0F, "width 1 truncation after ArithImm");
    CHECK(program.registers[4] == 0xCAFEBABEull, "LoadRegMem reads the absolute address");
    CHECK(program.registers[5] == 0x12345678ull, "LoadRegMem adds the offset register (flags bit 0)");
    CHECK(mem_get(0x3020, 4) == 0x5A5A5A5Aull, "StoreStaticToReg writes rA + rB");
    CHECK(program.registers[1] == 0x3004, "StoreStaticToReg increments rA by the width (flags bit 1)");
    CHECK(program.registers[7] == 0x0000BEEFull, "LoadRegMemReg reads [rA + address]");
    CHECK(program.registers[8] == 0x77777777ull, "LoadRegMemRegReg reads [rA + rB]");
    CHECK(mem_get(0x3200, 2) == 0xABCDull, "StoreReg writes rB at [rA]");
    CHECK(program.registers[12] == 0x55, "RestoreRegs brings the saved register back");

    /* ArithImm の連鎖だけを別ブロックで見る（上のブロックは r1 を後で
       作り直すので、最後に残る値では連鎖を確認できない）。 */
    mock_reset();
    nxusCheatReset(&program);
    wire_begin(1, 5);
    wire_block_set(0, 1, 0, 5, 1);
    wire_insn_set(0, NxusCheatOp_LoadRegImm, 0, 0, 0, 1, 0, 0, 0, 0, 0x1000);
    wire_insn_set(1, NxusCheatOp_ArithImm, 4, 0, NxusCheatArith_Add, 1, 0, 0, 0, 0, 0x20);
    wire_insn_set(2, NxusCheatOp_ArithImm, 4, 0, NxusCheatArith_Sub, 1, 0, 0, 0, 0, 0x20);
    wire_insn_set(3, NxusCheatOp_ArithImm, 4, 0, NxusCheatArith_Mul, 1, 0, 0, 0, 0, 2);
    wire_insn_set(4, NxusCheatOp_ArithImm, 4, 0, NxusCheatArith_Rsh, 1, 0, 0, 0, 0, 4);
    CHECK(nxusCheatInstall(&program, g_wire, wire_length()) == 0, "arithmetic chain program installs");
    CHECK(nxusCheatRunBlock(&program, 0, &g_io, 0, &g_journal) == NXUS_CHEATVM_OK,
          "arithmetic chain program runs");
    CHECK(program.registers[1] == 0x200, "ArithImm add/sub/mul/shift chain");

    /* 幅の違う演算とレジスタ比較。 */
    mock_reset();
    nxusCheatReset(&program);
    /* 0: r1 = 5, r2 = 6
       1: if r1 == r2 -> 4 (Equal, 即値なし・reg_b 比較: flags=1)
       2: [0x2800] = 1
       3: end
       4: [0x2804] = 2
       5: end                                        */
    wire_begin(1, 6);
    wire_block_set(0, 1, 0, 6, 1);
    wire_insn_set(0, NxusCheatOp_LoadRegImm, 0, 0, 0, 1, 0, 0, 0, 0, 5);
    wire_insn_set(1, NxusCheatOp_LoadRegImm, 0, 0, 0, 2, 0, 0, 0, 0, 6);
    wire_insn_set(2, NxusCheatOp_RegConditional, 4, 0, NxusCheatCmp_Equal, 1, 2, 1, 5, 0, 0);
    wire_insn_set(3, NxusCheatOp_StoreStatic, 4, NxusCheatRegion_Absolute, 0, 0, 0, 0, 0, 0x2800, 1);
    wire_insn_set(4, NxusCheatOp_EndConditional, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    wire_insn_set(5, NxusCheatOp_StoreStatic, 4, NxusCheatRegion_Absolute, 0, 0, 0, 0, 0, 0x2804, 2);
    CHECK(nxusCheatInstall(&program, g_wire, wire_length()) == 0, "RegConditional program installs");
    (void)nxusCheatTick(&program, &g_io, 0, &g_journal);
    CHECK(writes_at(0x2800, 4) == 0, "r1 != r2 skips the then-body");
    CHECK(writes_at(0x2804, 4) == 1, "r1 != r2 takes the jump target");
    nxusCheatProgramRelease(&program);
}

/* ======================================================================== */
/* patch は 1 回だけ / loop は毎回                                          */
/* ======================================================================== */

static void test_patch_once_loop_every_tick(void) {
    NxusCheatProgram program;

    printf("- patch once / loop every tick\n");
    mock_reset();
    nxusCheatProgramInit(&program);

    wire_begin(2, 2);
    wire_block_set(0, 0, 0, 1, 1); /* patch */
    wire_block_set(1, 1, 1, 1, 1); /* loop  */
    wire_insn_set(0, NxusCheatOp_StoreStatic, 4, NxusCheatRegion_Absolute, 0, 0, 0, 0, 0, 0x2000, 0x11111111ull);
    wire_insn_set(1, NxusCheatOp_StoreStatic, 4, NxusCheatRegion_Absolute, 0, 0, 0, 0, 0, 0x2010, 0x22222222ull);
    CHECK(nxusCheatInstall(&program, g_wire, wire_length()) == 0, "patch/loop program installs");

    CHECK(nxusCheatTick(&program, &g_io, 0, &g_journal) == 2, "first tick runs both blocks");
    (void)nxusCheatTick(&program, &g_io, 0, &g_journal);
    (void)nxusCheatTick(&program, &g_io, 0, &g_journal);
    CHECK(writes_at(0x2000, 4) == 1, "the patch block wrote exactly once");
    CHECK(writes_at(0x2010, 4) == 3, "the loop block wrote on every tick");
    CHECK(program.state[0].execs == 1, "patch exec count");
    CHECK(program.state[1].execs == 3, "loop exec count");
    CHECK(program.tick_count == 3, "tick counter");

    /* 再有効化したら patch はもう一度走る。 */
    CHECK(nxusCheatSetEnabled(&program, 0, false) == 0, "disable block 0");
    (void)nxusCheatTick(&program, &g_io, 0, &g_journal);
    CHECK(nxusCheatSetEnabled(&program, 0, true) == 0, "re-enable block 0");
    (void)nxusCheatTick(&program, &g_io, 0, &g_journal);
    CHECK(writes_at(0x2000, 4) == 2, "re-enabling a patch block runs it again");
    nxusCheatProgramRelease(&program);
}

/* ======================================================================== */
/* ステップ上限                                                             */
/* ======================================================================== */

static void test_step_limit(void) {
    NxusCheatProgram program;

    printf("- step limit\n");
    mock_reset();
    nxusCheatProgramInit(&program);

    wire_begin(1, 3);
    wire_block_set(0, 1, 0, 3, 1);
    wire_insn_set(0, NxusCheatOp_LoopStart, 0, 0, 0, 0, 0, 0, 1, 0, 1000000);
    wire_insn_set(1, NxusCheatOp_Nop, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    wire_insn_set(2, NxusCheatOp_LoopEnd, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    CHECK(nxusCheatInstall(&program, g_wire, wire_length()) == 0, "runaway loop installs");
    CHECK(nxusCheatRunBlock(&program, 0, &g_io, 0, &g_journal) == NXUS_CHEATVM_ERR_STEP_LIMIT,
          "a runaway loop is stopped by the step limit");

    (void)nxusCheatTick(&program, &g_io, 0, &g_journal);
    CHECK(program.state[0].last_error == (u32)NXUS_CHEATVM_ERR_STEP_LIMIT,
          "the step limit is recorded in last_error");
    CHECK(program.state[0].error_pc <= 2, "error_pc stays inside the block that overran");
    nxusCheatProgramRelease(&program);
}

/* ======================================================================== */
/* ジャーナル                                                               */
/* ======================================================================== */

static void test_journal(void) {
    NxusCheatProgram program;

    printf("- journal\n");
    mock_reset();
    nxusCheatProgramInit(&program);
    mem_put(0x2200, 0x11223344ull, 4);

    wire_begin(1, 1);
    wire_block_set(0, 1, 0, 1, 1);
    wire_insn_set(0, NxusCheatOp_StoreStatic, 4, NxusCheatRegion_Absolute, 0, 0, 0, 0, 0, 0x2200, 0xAABBCCDDull);
    CHECK(nxusCheatInstall(&program, g_wire, wire_length()) == 0, "journal program installs");

    (void)nxusCheatTick(&program, &g_io, 0, &g_journal);
    CHECK(g_journal.count == 1, "the first write is journalled");
    CHECK(g_journal.entries[0].original[0] == 0x44 && g_journal.entries[0].original[3] == 0x11,
          "the ORIGINAL bytes are captured, little-endian");
    CHECK(g_journal.entries[0].owners == 1, "owner count starts at 1");
    CHECK(mem_get(0x2200, 4) == 0xAABBCCDDull, "the patch landed");

    (void)nxusCheatTick(&program, &g_io, 0, &g_journal);
    CHECK(g_journal.count == 1, "a second write to the same address does not add an entry");
    CHECK(g_journal.entries[0].owners == 2, "the owner count is bumped instead");

    CHECK(nxusCheatJournalRestore(&g_journal, &g_io, true) == 1, "restore writes one address back");
    CHECK(mem_get(0x2200, 4) == 0x11223344ull, "the original value is back");
    CHECK(g_journal.count == 0, "a successfully restored entry is removed");

    /* 満杯の扱い（grow / 上限 16384 / 詰め直し）は
       test_journal_dynamic_capacity() で個別に検証する。旧実装は 512 件で
       固定され、513 件目以降の書き込みがすべて失敗していた。 */
    nxusCheatProgramRelease(&program);
}

/* ======================================================================== */
/* 失敗が次のブロックへ伝播しない                                           */
/* ======================================================================== */

static void test_failure_isolation(void) {
    NxusCheatProgram program;

    printf("- failures do not stop the following blocks\n");
    mock_reset();
    nxusCheatProgramInit(&program);

    wire_begin(2, 2);
    wire_block_set(0, 1, 0, 1, 1);
    wire_block_set(1, 1, 1, 1, 1);
    wire_insn_set(0, NxusCheatOp_StoreStatic, 4, NxusCheatRegion_Absolute, 0, 0, 0, 0, 0, 0x2400, 1);
    wire_insn_set(1, NxusCheatOp_StoreStatic, 4, NxusCheatRegion_Absolute, 0, 0, 0, 0, 0, 0x2410, 2);
    CHECK(nxusCheatInstall(&program, g_wire, wire_length()) == 0, "failure-isolation program installs");

    g_fail_write_on = true;
    g_fail_write_address = 0x2400;
    CHECK(nxusCheatTick(&program, &g_io, 0, &g_journal) == 2, "both blocks were attempted");
    CHECK(program.state[0].last_error == (u32)NXUS_CHEATVM_ERR_WRITE, "block 0 records the write failure");
    CHECK(program.state[0].error_pc == 0, "block 0's error_pc names its instruction");
    CHECK(writes_at(0x2410, 4) == 1, "block 1 still ran");
    CHECK(program.state[1].last_error == 0, "block 1 is clean");

    /* 読み失敗も同じ扱い（ERR_READ）。 */
    mock_reset();
    nxusCheatReset(&program);
    wire_begin(1, 2);
    wire_block_set(0, 1, 0, 2, 1);
    wire_insn_set(0, NxusCheatOp_BeginConditional, 4, NxusCheatRegion_Absolute, NxusCheatCmp_Equal,
                  0, 0, 0, 1, 0x2500, 1);
    wire_insn_set(1, NxusCheatOp_EndConditional, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    CHECK(nxusCheatInstall(&program, g_wire, wire_length()) == 0, "read-failure program installs");
    g_fail_read_on = true;
    g_fail_read_address = 0x2500;
    (void)nxusCheatTick(&program, &g_io, 0, &g_journal);
    CHECK(program.state[0].last_error == (u32)NXUS_CHEATVM_ERR_READ, "a read failure is reported as ERR_READ");

    /* ジャーナルに original を取れない場合も書かない。 */
    mock_reset();
    nxusCheatReset(&program);
    wire_begin(1, 1);
    wire_block_set(0, 1, 0, 1, 1);
    wire_insn_set(0, NxusCheatOp_StoreStatic, 4, NxusCheatRegion_Absolute, 0, 0, 0, 0, 0, 0x2600, 5);
    CHECK(nxusCheatInstall(&program, g_wire, wire_length()) == 0, "unreadable-original program installs");
    g_fail_read_on = true;
    g_fail_read_address = 0x2600;
    (void)nxusCheatTick(&program, &g_io, 0, &g_journal);
    CHECK(program.state[0].last_error == (u32)NXUS_CHEATVM_ERR_WRITE,
          "an unjournallable write is refused with ERR_WRITE");
    CHECK(g_write_log_count == 0, "nothing was written");
    nxusCheatProgramRelease(&program);
}

/* ======================================================================== */
/* 0xFF0 pause                                                              */
/* ======================================================================== */

static void test_pause(void) {
    NxusCheatProgram program;

    printf("- pause cuts the rest of the block\n");
    mock_reset();
    nxusCheatProgramInit(&program);

    wire_begin(1, 3);
    wire_block_set(0, 1, 0, 3, 1);
    wire_insn_set(0, NxusCheatOp_StoreStatic, 4, NxusCheatRegion_Absolute, 0, 0, 0, 0, 0, 0x2700, 0x11ull);
    wire_insn_set(1, NxusCheatOp_Pause, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    wire_insn_set(2, NxusCheatOp_StoreStatic, 4, NxusCheatRegion_Absolute, 0, 0, 0, 0, 0, 0x2710, 0x22ull);
    CHECK(nxusCheatInstall(&program, g_wire, wire_length()) == 0, "pause program installs");

    CHECK(nxusCheatTick(&program, &g_io, 0, &g_journal) == 1, "the paused block still counts as ran");
    CHECK(writes_at(0x2700, 4) == 1, "instructions before the pause ran");
    CHECK(writes_at(0x2710, 4) == 0, "instructions after the pause did not");
    CHECK(program.paused == true, "the program records the paused state");

    (void)nxusCheatTick(&program, &g_io, 0, &g_journal);
    CHECK(writes_at(0x2700, 4) == 2, "the next tick starts the block from the beginning");
    nxusCheatProgramRelease(&program);
}

/* ======================================================================== */
/* ヒープ命令配列: 必要分だけ確保し、解放できること                          */
/* ======================================================================== */

/* malloc 失敗を注入し、確保・解放の回数とサイズを数えるためのフック。 */
static u32 g_alloc_calls;
static u32 g_free_calls;
static size_t g_last_alloc_size;
static bool g_alloc_fail;

static void *counting_alloc(size_t size, void *user) {
    (void)user;
    g_alloc_calls++;
    g_last_alloc_size = size;
    if (g_alloc_fail) return NULL;
    return malloc(size);
}

static void counting_free(void *ptr, void *user) {
    (void)user;
    g_free_calls++;
    free(ptr);
}

/* 1 ブロック 1 命令の StoreStatic（enabled 指定可）。 */
static void build_single_store(u64 address, u64 value, u32 enabled) {
    wire_begin(1, 1);
    wire_block_set(0, 1, 0, 1, enabled);
    wire_insn_set(0, NxusCheatOp_StoreStatic, 4, NxusCheatRegion_Absolute, 0, 0, 0, 0, 0,
                  (u32)address, value);
}

static void test_program_heap_lifecycle(void) {
    NxusCheatProgram program;

    printf("- heap instruction array: init / install / reset / release\n");
    mock_reset();
    nxusCheatProgramInit(&program);

    CHECK(program.insns == NULL, "init leaves insns NULL");
    CHECK(program.insn_capacity == 0, "init leaves the capacity at zero");

    wire_begin(1, 2);
    wire_block_set(0, 1, 0, 2, 1);
    wire_insn_set(0, NxusCheatOp_StoreStatic, 4, NxusCheatRegion_Absolute, 0, 0, 0, 0, 0, 0x4100, 0xAAull);
    wire_insn_set(1, NxusCheatOp_Nop, 0, 0, 0, 0, 0, 0, 0, 0, 0);

    CHECK(nxusCheatInstall(&program, g_wire, wire_length()) == 0, "program installs");
    CHECK(program.insns != NULL, "install allocates the instruction array");
    CHECK(program.insn_capacity == 2, "capacity is exactly the installed instruction count");
    CHECK(sizeof(NxusCheatProgram) < 8u * 1024u,
          "the program struct no longer embeds 2048 instructions");
    CHECK(nxusCheatTick(&program, &g_io, 0, &g_journal) == 1, "the heap-backed program runs");
    CHECK(mem_get(0x4100, 4) == 0xAAull, "the heap-backed program wrote its value");

    /* reset は解放せず「空」にする。 */
    nxusCheatReset(&program);
    CHECK(program.insns != NULL, "reset keeps the allocated instruction array");
    CHECK(program.insn_capacity == 2, "reset keeps the capacity");
    CHECK(program.header.block_count == 0, "reset empties the program header");
    CHECK(nxusCheatTick(&program, &g_io, 0, &g_journal) == 0, "a reset program runs nothing");

    CHECK(nxusCheatInstall(&program, g_wire, wire_length()) == 0, "install after reset succeeds");
    CHECK(program.insn_capacity == 2, "install after reset reuses the same instruction count");

    nxusCheatProgramRelease(&program);
    CHECK(program.insns == NULL, "release clears insns");
    CHECK(program.insn_capacity == 0, "release clears the capacity");

    nxusCheatProgramRelease(&program);
    CHECK(program.insns == NULL, "a second release is safe (no double free)");
    CHECK(program.header.block_count == 0, "a second release leaves the program empty");

    /* release 後の再 install がリークせず動く。 */
    CHECK(nxusCheatInstall(&program, g_wire, wire_length()) == 0, "install after release succeeds");
    CHECK(program.insns != NULL, "install after release allocates again");
    nxusCheatProgramRelease(&program);
}

static void test_program_allocator_hook(void) {
    NxusCheatProgram program;

    printf("- allocation hook: failure injection and leak-free reinstall\n");
    mock_reset();
    nxusCheatProgramInit(&program);
    CHECK(NXUS_CHEATVM_ERR_NO_MEMORY == -9, "ERR_NO_MEMORY is -9");

    g_alloc_calls = 0;
    g_free_calls = 0;
    g_last_alloc_size = 0;
    g_alloc_fail = false;
    nxusCheatSetAllocator(counting_alloc, counting_free, NULL);

    /* A: 2 命令。 */
    wire_begin(1, 2);
    wire_block_set(0, 1, 0, 2, 1);
    wire_insn_set(0, NxusCheatOp_StoreStatic, 4, NxusCheatRegion_Absolute, 0, 0, 0, 0, 0, 0x4200, 0x1111ull);
    wire_insn_set(1, NxusCheatOp_Nop, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    CHECK(nxusCheatInstall(&program, g_wire, wire_length()) == 0, "install through the injected allocator");
    CHECK(g_alloc_calls == 1, "one allocation per install");
    CHECK(g_last_alloc_size == 2u * sizeof(NxusCheatInsn),
          "the allocation is exactly insn_count * sizeof(NxusCheatInsn)");

    /* 新規 program への確保失敗: 空のまま、壊れない。 */
    {
        NxusCheatProgram fresh;

        nxusCheatProgramInit(&fresh);
        build_single_store(0x4210, 0x2222, 0);
        g_alloc_fail = true;
        CHECK(nxusCheatInstall(&fresh, g_wire, wire_length()) == NXUS_CHEATVM_ERR_NO_MEMORY,
              "malloc failure returns ERR_NO_MEMORY (-9)");
        CHECK(fresh.insns == NULL, "a failed first install leaves no buffer behind");
        CHECK(fresh.insn_capacity == 0, "a failed first install leaves the capacity at zero");
        CHECK(fresh.header.block_count == 0, "a failed first install leaves the program empty");
        g_alloc_fail = false;
        nxusCheatProgramRelease(&fresh);
    }

    /* 既存 program への再確保失敗: 直前のプログラムがそのまま残る。 */
    build_single_store(0x4220, 0x3333, 1);
    g_alloc_fail = true;
    CHECK(nxusCheatInstall(&program, g_wire, wire_length()) == NXUS_CHEATVM_ERR_NO_MEMORY,
          "a failed reinstall returns ERR_NO_MEMORY");
    CHECK(program.insn_capacity == 2, "a failed reinstall keeps the installed capacity");
    CHECK(program.header.insn_count == 2, "a failed reinstall keeps the installed header");
    CHECK(g_free_calls == 0, "the old buffer is not freed before the new allocation succeeds");
    g_alloc_fail = false;
    CHECK(nxusCheatTick(&program, &g_io, 0, &g_journal) == 1,
          "the old program still runs after a failed reinstall");
    CHECK(mem_get(0x4200, 4) == 0x1111ull, "the old program still writes its value");

    /* 再 install 成功: 旧バッファは解放される（リークしない）。 */
    CHECK(nxusCheatInstall(&program, g_wire, wire_length()) == 0, "reinstall succeeds");
    CHECK(g_alloc_calls == 4, "every install attempt allocates once");
    CHECK(g_free_calls == 1, "a successful reinstall frees the previous buffer");
    CHECK(g_last_alloc_size == 1u * sizeof(NxusCheatInsn),
          "the new buffer is sized to the new (patch-sized) program");
    CHECK(program.insn_capacity == 1, "the new capacity is one instruction");
    CHECK(nxusCheatTick(&program, &g_io, 0, &g_journal) == 1, "the reinstalled program runs");
    CHECK(mem_get(0x4220, 4) == 0x3333ull, "the reinstalled program writes the new value");

    /* フックを既定へ戻した後でも、確保時の free で解放される。 */
    nxusCheatSetAllocator(NULL, NULL, NULL);
    nxusCheatProgramRelease(&program);
    CHECK(g_free_calls == 2, "release uses the allocator that produced the buffer");
    CHECK(program.insns == NULL, "release after restoring the hook clears insns");
    nxusCheatProgramRelease(&program);
    CHECK(g_free_calls == 2, "double release frees nothing a second time");
}

static void test_large_program_capacity(void) {
    NxusCheatProgram program;
    u8 *wire;
    size_t bytes;
    const u32 insn_count = 3000u;

    printf("- raised ceilings: a 3000-instruction program\n");
    mock_reset();
    nxusCheatProgramInit(&program);

    CHECK(NXUS_CHEATVM_MAX_INSNS == 20000u, "NXUS_CHEATVM_MAX_INSNS is 20000");
    CHECK(NXUS_CHEATVM_MAX_PROGRAM_BYTES == 512u * 1024u,
          "NXUS_CHEATVM_MAX_PROGRAM_BYTES is 512 KiB");

    bytes = sizeof(NxusCheatProgramHeader) + sizeof(NxusCheatBlockDesc) +
            (size_t)insn_count * sizeof(NxusCheatInsn);
    wire = (u8 *)malloc(bytes);
    CHECK(wire != NULL, "large wire buffer allocated");
    if (wire == NULL) {
        nxusCheatProgramRelease(&program);
        return;
    }

    memset(wire, 0, bytes); /* 全命令ゼロ = Nop */
    {
        NxusCheatProgramHeader *header = (NxusCheatProgramHeader *)wire;
        NxusCheatBlockDesc *block = (NxusCheatBlockDesc *)(wire + sizeof *header);

        header->magic = NXUS_CHEATVM_MAGIC;
        header->version = NXUS_CHEATVM_VERSION;
        header->block_count = 1;
        header->insn_count = insn_count;
        header->total_bytes = (u32)bytes;
        block->index = 0;
        block->mode = 1;
        block->first = 0;
        block->count = insn_count;
        block->enabled = 1;
    }

    CHECK(nxusCheatInstall(&program, wire, bytes) == 0,
          "a 3000-instruction program installs (the old ceiling was 2048)");
    CHECK(program.insn_capacity == insn_count, "capacity tracks the 3000 instructions");
    CHECK(nxusCheatRunBlock(&program, 0, &g_io, 0, &g_journal) == NXUS_CHEATVM_OK,
          "the 3000-instruction block runs");

    nxusCheatProgramRelease(&program);
    CHECK(program.insns == NULL, "the large buffer is released");
    free(wire);
}

/* ======================================================================== */
/* 復元表の動的容量（512 固定 → 必要に応じて grow、上限 16384）             */
/* ======================================================================== */

/*
 * 実機報告の再現: チートを ON にしていくと 512 件で復元表が満杯になり、
 * 以後「1 行のチートも」適用できなくなり、Switch を再起動するまで直らなかった。
 * ここでは
 *   - 512 を超えて記録できる（2000 件・600 ストアの実プログラム）、
 *   - 上限 16384 では ERR_JOURNAL_FULL を返し、IO へ書き込まない、
 *   - 復元に成功したエントリは消え、失敗したものだけ残る、
 *   - owners == 0 の詰め直しで grow せずに再利用できる、
 *   - 同じアドレスの再記録は original を保持する（既存挙動の回帰）
 * を確認する。
 */
static void test_journal_dynamic_capacity(void) {
    NxusCheatJournal journal;
    u32 index;
    bool all_ok;

    printf("- journal: dynamic capacity, grow, ceiling, compaction, restore release\n");

    CHECK(NXUS_CHEATVM_MAX_JOURNAL == 16384u, "NXUS_CHEATVM_MAX_JOURNAL is 16384");
    CHECK(NXUS_CHEATVM_ERR_JOURNAL_FULL == -10, "ERR_JOURNAL_FULL is -10");
    CHECK((u32)(-NXUS_CHEATVM_ERR_JOURNAL_FULL) == 10u,
          "the positive wire code of a journal-full failure is 10");

    /* ---- Init は指定容量を確保し、超えたら 2 倍に grow する ---- */
    mock_reset();
    CHECK(nxusCheatJournalInit(&journal, 4) == 0, "init with 4 slots succeeds");
    CHECK(journal.entries != NULL && journal.capacity == 4u && journal.count == 0u,
          "init allocates the requested capacity and starts empty");

    all_ok = true;
    for (index = 0; index < 4u; index++) {
        if (nxusCheatJournalRemember(&journal, &g_io, 0x1000u + index, 1, 0) != 0) all_ok = false;
    }
    CHECK(all_ok && journal.count == 4u && journal.capacity == 4u,
          "four addresses fill the initial capacity without growing");

    CHECK(nxusCheatJournalRemember(&journal, &g_io, 0x1010u, 1, 0) == 0,
          "the fifth address is accepted");
    CHECK(journal.capacity == 8u && journal.count == 5u,
          "the journal doubles instead of refusing");

    /* ---- 512 件の壁: 2000 個の異なるアドレスをすべて記録できる ---- */
    mock_reset();
    nxusCheatJournalReset(&journal);
    all_ok = true;
    for (index = 0; index < 2000u; index++) {
        if (nxusCheatJournalRemember(&journal, &g_io, 0x2000u + index, 1, 0) != 0) all_ok = false;
    }
    CHECK(all_ok, "2000 distinct addresses are all journalled (the old ceiling was 512)");
    CHECK(journal.count == 2000u, "count tracks the 2000 entries");
    CHECK(journal.capacity >= 2000u && journal.capacity <= NXUS_CHEATVM_MAX_JOURNAL,
          "capacity grew to fit them");

    /* ---- 実データ相当: 1 ブロックが 600 アドレスを書き換えても全部通る ---- */
    mock_reset();
    nxusCheatJournalReset(&journal);
    {
        NxusCheatProgram program;
        const u32 stores = 600u;

        nxusCheatProgramInit(&program);
        wire_begin(1, stores);
        wire_block_set(0, 1, 0, stores, 1);
        for (index = 0; index < stores; index++) {
            wire_insn_set(index, NxusCheatOp_StoreStatic, 4, NxusCheatRegion_Absolute, 0, 0, 0, 0,
                          0, 0x1000u + index * 4u, 0xA5A50000ull + index);
        }
        CHECK(nxusCheatInstall(&program, g_wire, wire_length()) == 0, "a 600-store program installs");
        CHECK(nxusCheatTick(&program, &g_io, 0, &journal) == 1, "the 600-store block runs");
        CHECK(journal.count == stores, "all 600 originals are journalled");
        CHECK(g_write_log_count == stores, "all 600 writes reached the IO");
        CHECK(mem_get(0x1000u + (u64)(stores - 1u) * 4u, 4) == 0xA5A50000ull + stores - 1u,
              "the last store landed");
        nxusCheatProgramRelease(&program);
    }

    /* ---- 同じアドレスの再記録は original を保持する（既存挙動の回帰） ---- */
    mock_reset();
    nxusCheatJournalReset(&journal);
    mem_put(0x3000, 0x11, 1);
    CHECK(nxusCheatJournalRemember(&journal, &g_io, 0x3000, 1, 0) == 0, "first record");
    mem_put(0x3000, 0x22, 1);   /* ブロックがパッチした後の値 */
    CHECK(nxusCheatJournalRemember(&journal, &g_io, 0x3000, 1, 0) == 0, "re-record");
    CHECK(journal.count == 1u && journal.entries[0].original[0] == 0x11,
          "a second write keeps the FIRST original");
    CHECK(journal.entries[0].owners == 2u, "the owner count is bumped instead");

    /* ---- 復元に成功したエントリは消える（配列は保持） ---- */
    CHECK(nxusCheatJournalRestore(&journal, &g_io, true) == 1, "restore writes the address back");
    CHECK(journal.count == 0u, "a successfully restored entry is removed");
    CHECK(journal.entries != NULL && journal.capacity != 0u,
          "the entry array is kept for reuse after a restore");
    CHECK(mem_get(0x3000, 1) == 0x11, "the original byte is back");

    /* ---- 復元に失敗したエントリだけが残り、再試行できる ---- */
    mock_reset();
    nxusCheatJournalReset(&journal);
    mem_put(0x3100, 0x77, 1);
    mem_put(0x3104, 0x88, 1);
    CHECK(nxusCheatJournalRemember(&journal, &g_io, 0x3100, 1, 0) == 0, "record A");
    CHECK(nxusCheatJournalRemember(&journal, &g_io, 0x3104, 1, 0) == 0, "record B");
    g_fail_write_on = true;
    g_fail_write_address = 0x3104;
    CHECK(nxusCheatJournalRestore(&journal, &g_io, true) == -1,
          "a partial restore reports failure");
    CHECK(journal.count == 1u && journal.entries[0].address == 0x3104u,
          "only the entry whose write-back failed is kept");
    CHECK(mem_get(0x3100, 1) == 0x77, "the successful address was restored");
    g_fail_write_on = false;
    CHECK(nxusCheatJournalRestore(&journal, &g_io, true) == 1, "the retry restores the kept entry");
    CHECK(journal.count == 0u, "the journal is empty after the retry");

    /* ---- owners == 0 の詰め直し: 満杯でも grow せずに再利用する ---- */
    mock_reset();
    nxusCheatJournalRelease(&journal);
    CHECK(nxusCheatJournalInit(&journal, 4) == 0, "a fresh 4-slot journal for the compaction check");
    all_ok = true;
    for (index = 0; index < 4u; index++) {
        if (nxusCheatJournalRemember(&journal, &g_io, 0x3200u + index, 1, 0) != 0) all_ok = false;
    }
    CHECK(all_ok && journal.count == 4u && journal.capacity == 4u,
          "the journal is full at 4/4 before the compaction check");
    journal.entries[1].owners = 0;   /* 復元済みの死んだエントリを模す */
    journal.entries[3].owners = 0;
    CHECK(nxusCheatJournalRemember(&journal, &g_io, 0x3210u, 1, 0) == 0,
          "a new address fits after compacting the dead entries");
    CHECK(journal.capacity == 4u, "the dead entries were reused instead of growing");
    CHECK(journal.count == 3u, "two dead entries dropped, one added");
    CHECK(journal.entries[0].address == 0x3200u && journal.entries[1].address == 0x3202u &&
          journal.entries[2].address == 0x3210u,
          "compaction keeps the live entries in order");

    /* ---- 上限 16384: それ以上は ERR_JOURNAL_FULL で「書かない」 ---- */
    mock_reset();
    nxusCheatJournalRelease(&journal);
    CHECK(nxusCheatJournalInit(&journal, NXUS_CHEATVM_MAX_JOURNAL) == 0,
          "init at the ceiling succeeds");
    all_ok = true;
    for (index = 0; index < NXUS_CHEATVM_MAX_JOURNAL; index++) {
        if (nxusCheatJournalRemember(&journal, &g_io, 0x4000u + index, 1, 0) != 0) all_ok = false;
    }
    CHECK(all_ok, "all 16384 addresses fit the ceiling");
    CHECK(journal.count == NXUS_CHEATVM_MAX_JOURNAL &&
          journal.capacity == NXUS_CHEATVM_MAX_JOURNAL,
          "the journal is exactly at its ceiling");
    CHECK(nxusCheatJournalRemember(&journal, &g_io, 0x4000u + NXUS_CHEATVM_MAX_JOURNAL, 1, 0)
              == NXUS_CHEATVM_ERR_JOURNAL_FULL,
          "one more address is refused with ERR_JOURNAL_FULL (-10)");
    CHECK(journal.count == NXUS_CHEATVM_MAX_JOURNAL, "the refused address is not recorded");

    /* ---- VM の書き込みパスが -10 を伝播し、IO へ書き込まない ---- */
    {
        NxusCheatProgram program;

        nxusCheatProgramInit(&program);
        build_single_store(0x8000, 0xAA, 1);
        CHECK(nxusCheatInstall(&program, g_wire, wire_length()) == 0, "ceiling program installs");
        CHECK(nxusCheatRunBlock(&program, 0, &g_io, 0, &journal) == NXUS_CHEATVM_ERR_JOURNAL_FULL,
              "the VM propagates ERR_JOURNAL_FULL from the write path");
        CHECK(g_write_log_count == 0, "the refused write never reaches the IO");
        CHECK(mem_get(0x8000, 4) == 0, "the target is untouched");
        nxusCheatProgramRelease(&program);
    }

    /* ---- Release と、Init していないジャーナル ---- */
    nxusCheatJournalRelease(&journal);
    CHECK(journal.entries == NULL && journal.capacity == 0u && journal.count == 0u,
          "release frees the entry array");
    nxusCheatJournalRelease(&journal);
    CHECK(journal.entries == NULL, "a second release is safe");

    memset(&journal, 0, sizeof journal);
    CHECK(nxusCheatJournalRemember(&journal, &g_io, 0x9000, 1, 0) == 0,
          "a zero-initialised journal grows on its first write");
    CHECK(journal.entries != NULL && journal.capacity >= 1u && journal.count == 1u,
          "the lazy grow allocated an array");
    nxusCheatJournalRelease(&journal);
}

/* ======================================================================== */

int main(void) {
    printf("=== Nxus cheat VM host tests ===\n");
    printf("sizeof(NxusCheatInsn)=%u sizeof(NxusCheatBlockDesc)=%u sizeof(NxusCheatProgramHeader)=%u\n",
           (unsigned)sizeof(NxusCheatInsn), (unsigned)sizeof(NxusCheatBlockDesc),
           (unsigned)sizeof(NxusCheatProgramHeader));

    CHECK(sizeof(NxusCheatInsn) == 24, "NxusCheatInsn stays 24 bytes on the wire");
    CHECK(sizeof(NxusCheatBlockDesc) == 24, "NxusCheatBlockDesc stays 24 bytes on the wire");
    CHECK(sizeof(NxusCheatJournalEntry) == 24, "NxusCheatJournalEntry stays 24 bytes");

    /* 復元表は Init で確保する（テスト全体で 1 本を使い回す）。 */
    CHECK(nxusCheatJournalInit(&g_journal, 512) == 0, "the test journal starts at 512 slots");

    test_install_validation();
    test_store_static_widths_and_regions();
    test_conditional_and_else();
    test_loop();
    test_keypress_conditional();
    test_register_operations();
    test_patch_once_loop_every_tick();
    test_step_limit();
    test_journal();
    test_failure_isolation();
    test_pause();
    test_program_heap_lifecycle();
    test_program_allocator_hook();
    test_large_program_capacity();
    test_journal_dynamic_capacity();

    nxusCheatJournalRelease(&g_journal);

    printf("=== %d checks, %d failures ===\n", g_checks, g_failures);
    if (g_failures == 0) printf("ALL CHEAT VM TESTS PASSED\n");
    return g_failures == 0 ? 0 : 1;
}
