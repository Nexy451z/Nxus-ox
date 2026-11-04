/* コンソール側チート VM (core/nxus_cheatvm.c) のホストテスト。
 *
 * なぜモック IO か: 実機の dmnt:cht を挟まずに「どのアドレスへ何バイト、
 * どの値で書いたか」を厳密に観測するため。失敗注入もここで行う。
 * メモリは 64 KiB の配列で、アドレス = 配列の添字（領域ベースは PC が解決して
 * 送る契約なので、テストも最終アドレスを直接使う）。
 */
#include <stdio.h>
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
    nxusCheatReset(&program);

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
}

/* ======================================================================== */
/* StoreStatic: 幅と領域                                                    */
/* ======================================================================== */

static void test_store_static_widths_and_regions(void) {
    NxusCheatProgram program;

    printf("- StoreStatic: widths, truncation, regions\n");
    mock_reset();
    nxusCheatReset(&program);

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
}

/* ======================================================================== */
/* 条件分岐（真・偽・Else）                                                  */
/* ======================================================================== */

static void test_conditional_and_else(void) {
    NxusCheatProgram program;

    printf("- conditionals: true / false / else\n");
    mock_reset();
    nxusCheatReset(&program);

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
}

/* ======================================================================== */
/* ループ                                                                   */
/* ======================================================================== */

static void test_loop(void) {
    NxusCheatProgram program;

    printf("- loops\n");
    mock_reset();
    nxusCheatReset(&program);

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
}

/* ======================================================================== */
/* キー条件                                                                 */
/* ======================================================================== */

static void test_keypress_conditional(void) {
    NxusCheatProgram program;

    printf("- keypress conditional (all bits AND)\n");
    mock_reset();
    nxusCheatReset(&program);

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
}

/* ======================================================================== */
/* レジスタ演算                                                             */
/* ======================================================================== */

static void test_register_operations(void) {
    NxusCheatProgram program;

    printf("- register operations\n");
    mock_reset();
    nxusCheatReset(&program);

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
}

/* ======================================================================== */
/* patch は 1 回だけ / loop は毎回                                          */
/* ======================================================================== */

static void test_patch_once_loop_every_tick(void) {
    NxusCheatProgram program;

    printf("- patch once / loop every tick\n");
    mock_reset();
    nxusCheatReset(&program);

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
}

/* ======================================================================== */
/* ステップ上限                                                             */
/* ======================================================================== */

static void test_step_limit(void) {
    NxusCheatProgram program;

    printf("- step limit\n");
    mock_reset();
    nxusCheatReset(&program);

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
}

/* ======================================================================== */
/* ジャーナル                                                               */
/* ======================================================================== */

static void test_journal(void) {
    NxusCheatProgram program;

    printf("- journal\n");
    mock_reset();
    nxusCheatReset(&program);
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

    /* 満杯: 513 個目の書き込みは実行せず、そのブロックを ERR_WRITE で止める。 */
    mock_reset();
    nxusCheatReset(&program);
    wire_begin(1, 4);
    wire_block_set(0, 1, 0, 4, 1);
    wire_insn_set(0, NxusCheatOp_LoadRegImm, 0, 0, 0, 1, 0, 0, 0, 0, 0x1000);
    wire_insn_set(1, NxusCheatOp_LoopStart, 0, 0, 0, 0, 0, 0, 2, 0, NXUS_CHEATVM_MAX_JOURNAL + 1u);
    wire_insn_set(2, NxusCheatOp_StoreStaticToReg, 4, 0, 0, 1, 0, 2, 0, 0, 0xDEADBEEFull);
    wire_insn_set(3, NxusCheatOp_LoopEnd, 0, 0, 0, 0, 0, 0, 1, 0, 0);
    CHECK(nxusCheatInstall(&program, g_wire, wire_length()) == 0, "journal-overflow program installs");
    (void)nxusCheatTick(&program, &g_io, 0, &g_journal);
    CHECK(g_journal.count == NXUS_CHEATVM_MAX_JOURNAL, "the journal fills to its capacity");
    CHECK(program.state[0].last_error == (u32)NXUS_CHEATVM_ERR_WRITE,
          "the write that would overflow the journal fails with ERR_WRITE");
    CHECK(mem_get(0x1000 + (u64)NXUS_CHEATVM_MAX_JOURNAL * 4u, 4) == 0,
          "that write is refused, not applied");
    CHECK(writes_at(0x1000 + (u64)NXUS_CHEATVM_MAX_JOURNAL * 4u, 4) == 0,
          "the refused address never reaches the IO");
}

/* ======================================================================== */
/* 失敗が次のブロックへ伝播しない                                           */
/* ======================================================================== */

static void test_failure_isolation(void) {
    NxusCheatProgram program;

    printf("- failures do not stop the following blocks\n");
    mock_reset();
    nxusCheatReset(&program);

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
}

/* ======================================================================== */
/* 0xFF0 pause                                                              */
/* ======================================================================== */

static void test_pause(void) {
    NxusCheatProgram program;

    printf("- pause cuts the rest of the block\n");
    mock_reset();
    nxusCheatReset(&program);

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
}

/* ======================================================================== */

int main(void) {
    printf("=== Nxus cheat VM host tests ===\n");
    printf("sizeof(NxusCheatInsn)=%u sizeof(NxusCheatBlockDesc)=%u sizeof(NxusCheatProgramHeader)=%u\n",
           (unsigned)sizeof(NxusCheatInsn), (unsigned)sizeof(NxusCheatBlockDesc),
           (unsigned)sizeof(NxusCheatProgramHeader));

    CHECK(sizeof(NxusCheatInsn) == 24, "NxusCheatInsn stays 24 bytes on the wire");
    CHECK(sizeof(NxusCheatBlockDesc) == 24, "NxusCheatBlockDesc stays 24 bytes on the wire");

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

    printf("=== %d checks, %d failures ===\n", g_checks, g_failures);
    if (g_failures == 0) printf("ALL CHEAT VM TESTS PASSED\n");
    return g_failures == 0 ? 0 : 1;
}
