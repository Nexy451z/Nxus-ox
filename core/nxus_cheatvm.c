/**
 * @file nxus_cheatvm.c
 * @brief コンソール側チート解釈実行エンジン（C・libnx 非依存）。
 *
 * 何をするか
 * ----------
 * PC がパース済み・リンク済みのプログラム（分岐先 = 命令インデックス）を
 * 受け取り、検証して保持し、16 ms ワーカーから 1 tick ずつ実行する。
 * メモリアクセスは NxusCheatIo 越しなので、ホストテストではメモリ配列、
 * 実機では dmnt:cht をそのまま差し込める。
 *
 * 参照実装（pc/Nxus.Cli/src/cheat/vm.rs）との関係
 * -----------------------------------------------
 * 意味論（幅の切り詰め・レジスタ・条件比較・ループ・キー条件）は Rust 版に
 * 合わせる。違うのは IR がすでにリンク済みである点だけで、Rust 版が
 * JumpInfo テーブルから引いていた分岐先は、ここでは insn.target をそのまま使う。
 * したがって Else は pc = target、EndConditional は素通り、LoopEnd は
 * カウンタが残っていれば pc = target（= LoopStart）、LoopStart は
 * rA = value（カウンタ設定）で本体へ落ちる。
 *
 * アドレス契約（ヘッダの "Address contract"）
 * -------------------------------------------
 * PC がアップロード前に region + offset を最終絶対アドレスへ解決する。よって
 * ここでは領域ベースを足さない（cheatRegionBase）。region は検証とログのため
 * に受け取るだけ。安全は同一性（build_id / program_id）と dmnt incarnation で
 * 担保する、というのがヘッダの設計。
 */

#include "nxus_cheatvm.h"

#include <stdlib.h>
#include <string.h>

/* install が返す -1..-5 はヘッダのコメントでしか名前が付いていないので、
   ここで対応する名前を定義する。 */
#define CHEAT_ERR_BAD_MAGIC (-1)  /* magic / version 不一致      */
#define CHEAT_ERR_BAD_SIZE (-2)   /* total_bytes / 実長の不一致  */
#define CHEAT_ERR_BAD_BLOCK (-3)  /* ブロック・命令の内容不正    */
#define CHEAT_ERR_BAD_TARGET (-4) /* 分岐先がブロック外          */
#define CHEAT_ERR_TOO_MANY (-5)   /* 命令数が上限超え            */

/* ======================================================================== */
/* 小さなユーティリティ                                                     */
/* ======================================================================== */

/**
 * 幅に合わせて値を切り詰める。
 *
 * なぜ必要か: Atmosphere のチートコードは「書く幅」だけを指定し、値の上位
 * ビットは無視する。Rust 版も truncate() で同じことをしており、条件比較の
 * 期待値・レジスタ演算の結果もこの規則で丸められる。
 */
static u64 cheatTruncate(u64 value, u32 width) {
    switch (width) {
        case 1: return value & 0xFFull;
        case 2: return value & 0xFFFFull;
        case 4: return value & 0xFFFFFFFFull;
        default: return value; /* 8、および幅を持たない命令 (0) はそのまま */
    }
}

/** チートコードが使う幅か（0 は「この命令は幅を使わない」の意）。 */
static bool cheatWidthOk(u32 width) {
    return width == 0 || width == 1 || width == 2 || width == 4 || width == 8;
}

/**
 * 領域ベース。
 *
 * ヘッダの NxusCheatProgram にはベースを置く欄が無いため、ここでは常に 0 を
 * 返す = address は PC が解決済みの最終アドレスという契約。PC は
 * アップロード時点の Metadata（main/heap/alias/aslr）を持っているので、
 * 相対アドレスを絶対アドレスへ直してから送れる。
 *
 * 将来コンソール側でベースを足す必要が出たら、この 1 関数だけを差し替えれば
 * よい（呼び出し側はすべて cheatResolve() を通している）。
 */
static u64 cheatRegionBase(u32 region) {
    (void)region;
    return 0;
}

/** `[region + relative (+ extra)]` を最終アドレスへ解決する。 */
static u64 cheatResolve(u32 region, u64 relative, u64 extra) {
    /* u64 の加算はラップしてよい: Atmosphere も 64bit 加算の桁溢れを黙って
       巻き戻すだけで、範囲外アドレスは次の read/write が失敗する。 */
    return cheatRegionBase(region) + relative + extra;
}

/** この op は target を分岐先として使うか（install の範囲検証の対象）。 */
static bool cheatIsBranch(u32 op) {
    switch (op) {
        case NxusCheatOp_BeginConditional:
        case NxusCheatOp_Else:
        case NxusCheatOp_LoopEnd:
        case NxusCheatOp_RegConditional:
        case NxusCheatOp_KeypressConditional:
            return true;
        default:
            /* LoopStart の target は「本体の先頭」を指す情報で、実行は必ず
               次の命令へ落ちる。分岐ではないので範囲検証しない。 */
            return false;
    }
}

/** 条件比較（Atmosphere の番号）。 */
static bool cheatCompare(u32 cmp, u64 left, u64 right) {
    switch (cmp) {
        case NxusCheatCmp_Greater:      return left > right;
        case NxusCheatCmp_GreaterEqual: return left >= right;
        case NxusCheatCmp_Less:         return left < right;
        case NxusCheatCmp_LessEqual:    return left <= right;
        case NxusCheatCmp_Equal:        return left == right;
        case NxusCheatCmp_NotEqual:     return left != right;
        default:                        return false;
    }
}

/**
 * レジスタ演算（Atmosphere の番号）。
 *
 * シフト量を 63 でマスクするのは Rust 版と同じ。マスクしないと C では
 * 64 以上のシフトが未定義動作になり、テスト環境と実機で結果が変わりうる。
 */
static u64 cheatArith(u32 op, u64 left, u64 right) {
    switch (op) {
        case NxusCheatArith_Add: return left + right;
        case NxusCheatArith_Sub: return left - right;
        case NxusCheatArith_Mul: return left * right;
        case NxusCheatArith_Lsh: return left << (right & 63u);
        case NxusCheatArith_Rsh: return left >> (right & 63u);
        default: return left;
    }
}

/* ======================================================================== */
/* 命令配列のアロケータ                                                     */
/* ======================================================================== */

/*
 * 命令配列だけをヒープに置く。patch 型チートは 1 命令でも、loop 型は
 * 20000 命令でも、実際に必要な分だけ確保する（旧実装は全プログラムが
 * 2048 命令分の固定配列を常駐させていた）。
 *
 * フックはホストテストの malloc 失敗注入のために公開している。実機では
 * 既定の malloc/free のまま。プログラムは確保時の free 関数を覚えるので、
 * フックを戻したあとに release しても食い違わない。
 */
static void *cheatDefaultAlloc(size_t size, void *user) {
    (void)user;
    return malloc(size);
}

static void cheatDefaultFree(void *ptr, void *user) {
    (void)user;
    free(ptr);
}

static NxusCheatAllocFn g_cheat_alloc = cheatDefaultAlloc;
static NxusCheatFreeFn g_cheat_free = cheatDefaultFree;
static void *g_cheat_alloc_user = NULL;

void nxusCheatSetAllocator(NxusCheatAllocFn alloc, NxusCheatFreeFn release, void *user) {
    g_cheat_alloc = (alloc != NULL) ? alloc : cheatDefaultAlloc;
    g_cheat_free = (release != NULL) ? release : cheatDefaultFree;
    g_cheat_alloc_user = user;
}

/**
 * program が持つ命令配列を解放して NULL に戻す。確保時の free を使う。
 *
 * 何度呼んでも安全: insns が NULL なら何もしない（二重解放しない）。
 */
static void cheatProgramFreeInsns(NxusCheatProgram *program) {
    if (program->insns != NULL) {
        NxusCheatFreeFn release =
            (program->insns_free != NULL) ? program->insns_free : cheatDefaultFree;
        release(program->insns, program->insns_free_user);
    }
    program->insns = NULL;
    program->insn_capacity = 0;
    program->insns_free = NULL;
    program->insns_free_user = NULL;
}

/* ======================================================================== */
/* メモリアクセス（IO 経由・リトルエンディアン・未整列アクセス禁止）        */
/* ======================================================================== */

/**
 * width バイトを読む。
 *
 * なぜ memcpy か: NxusCheatIo は任意のアドレスを渡される。u64* へキャストして
 * 直接読むと未整列アクセスになり、AArch64 では（設定次第で）トラップする。
 * ここで 1 バイトずつ組み立てれば、整列もエンディアンも明示的になる。
 */
static int cheatReadValue(const NxusCheatIo *io, u64 address, u32 width, u64 *out) {
    u8 bytes[8];
    u32 index;
    u64 value = 0;

    if (io == NULL || io->read == NULL) return NXUS_CHEATVM_ERR_READ;
    if (!(width == 1 || width == 2 || width == 4 || width == 8)) return NXUS_CHEATVM_ERR_BAD_OPCODE;

    memset(bytes, 0, sizeof bytes);
    if (io->read(io->user, address, bytes, width) != 0) return NXUS_CHEATVM_ERR_READ;

    for (index = 0; index < width; index++) {
        value |= (u64)bytes[index] << (8u * index);
    }
    *out = value;
    return NXUS_CHEATVM_OK;
}

/**
 * width バイトを書く。書く前に必ずジャーナルへ original を記録する。
 *
 * ジャーナルが満杯なら「そのブロックの書き込みを中止」して ERR_WRITE を返す。
 * ここで書き込んでしまうと Panic Restore がそのアドレスを戻せず、タイトルを
 * 再起動するまでチートが残る（安全側に倒す、という要件）。
 *
 * allow_rx は常に true: チートの書き込み先は RX のコードページであることが
 * あり、PC 版も io.write_mem(..., true) で送っている。実際に書いてよいかの
 * 判断は IO 側（dmnt ラッパー）がマッピング権限で行う。
 */
static int cheatWriteValue(const NxusCheatIo *io, NxusCheatJournal *journal, u64 address,
                           u32 width, u64 value, u8 owner) {
    u8 bytes[8];
    u32 index;

    if (io == NULL || io->write == NULL) return NXUS_CHEATVM_ERR_WRITE;
    if (!(width == 1 || width == 2 || width == 4 || width == 8)) return NXUS_CHEATVM_ERR_BAD_OPCODE;
    /* 記録できない書き込みは Panic Restore で戻せないので、書かずに失敗させる。 */
    if (journal == NULL) return NXUS_CHEATVM_ERR_WRITE;

    for (index = 0; index < width; index++) {
        bytes[index] = (u8)(value >> (8u * index));
    }

    /* 書き込み前に original を確保できなければ、この書き込みは行わない。 */
    if (nxusCheatJournalRemember(journal, io, address, width, owner) != 0) {
        return NXUS_CHEATVM_ERR_WRITE;
    }

    if (io->write(io->user, address, bytes, width, true) != 0) return NXUS_CHEATVM_ERR_WRITE;
    return NXUS_CHEATVM_OK;
}

/* ======================================================================== */
/* ジャーナル（元バイトの保存・Panic Restore）                              */
/* ======================================================================== */

void nxusCheatJournalReset(NxusCheatJournal *journal) {
    if (journal == NULL) return;
    memset(journal->entries, 0, sizeof journal->entries);
    journal->count = 0;
    journal->capacity = NXUS_CHEATVM_MAX_JOURNAL;
}

int nxusCheatJournalRemember(NxusCheatJournal *journal, const NxusCheatIo *io, u64 address,
                             u32 width, u8 owner) {
    u32 capacity;
    u32 index;
    NxusCheatJournalEntry *entry;

    /* owner は「どのブロックが書いたか」。NxusCheatJournalEntry には
       オーナーのビット表を置く欄が無い（ヘッダは変更禁止）ので、ここでは
       owners を「このアドレスを触った回数」として数えるだけに留める。
       引数は将来のログ用に受け取る形を保っている。 */
    (void)owner;

    if (journal == NULL || io == NULL || io->read == NULL) return -1;
    if (width == 0 || width > 8) return -1;

    capacity = journal->capacity;
    if (capacity > NXUS_CHEATVM_MAX_JOURNAL) capacity = NXUS_CHEATVM_MAX_JOURNAL;

    /* すでに記録済みのアドレスなら original は初回のまま維持する。ここで
       読み直すと「すでにパッチされた後の値」を original として保存してしまい、
       Panic Restore が元に戻せなくなる。 */
    for (index = 0; index < journal->count && index < capacity; index++) {
        if (journal->entries[index].address == address) {
            if (journal->entries[index].owners < 0xFFu) journal->entries[index].owners++;
            return 0;
        }
    }

    if (journal->count >= capacity) return -1; /* 満杯: 呼び出し側は書かない */

    entry = &journal->entries[journal->count];
    memset(entry, 0, sizeof *entry);
    entry->address = address;
    entry->width = (u8)width;
    if (io->read(io->user, address, entry->original, width) != 0) {
        /* original を確保できない = 復元できない。記録せずに拒否する。 */
        entry->address = 0;
        entry->width = 0;
        return -1;
    }
    entry->owners = 1;
    journal->count++;
    return 0;
}

int nxusCheatJournalRestore(NxusCheatJournal *journal, const NxusCheatIo *io, bool allow_rx) {
    u32 capacity;
    u32 index;
    int restored = 0;
    bool failed = false;

    if (journal == NULL || io == NULL || io->write == NULL) return -1;

    capacity = journal->capacity;
    if (capacity > NXUS_CHEATVM_MAX_JOURNAL) capacity = NXUS_CHEATVM_MAX_JOURNAL;

    /* 1 件失敗しても残りは戻す: 戻せるものを戻したほうが被害が小さい。
       ただし「全部戻せた」とは言えないので戻り値は負にする。ジャーナルは
       消さない（失敗したぶんを再試行できるようにする）。 */
    for (index = 0; index < journal->count && index < capacity; index++) {
        const NxusCheatJournalEntry *entry = &journal->entries[index];
        if (entry->width == 0 || entry->width > 8) continue;
        if (io->write(io->user, entry->address, entry->original, entry->width, allow_rx) != 0) {
            failed = true;
            continue;
        }
        restored++;
    }

    if (failed) return -1;
    return restored;
}

/* ======================================================================== */
/* プログラムの設置                                                         */
/* ======================================================================== */

void nxusCheatProgramInit(NxusCheatProgram *program) {
    if (program == NULL) return;
    /* ゼロが「空・全部無効・未確保」を意味する。ここでは解放しない:
       未初期化のポインタを free してしまうほうが危険であり、確保済みの
       program に対して呼ぶのは呼び出し側の契約違反（ヘッダに明記）。 */
    memset(program, 0, sizeof *program);
}

void nxusCheatProgramRelease(NxusCheatProgram *program) {
    if (program == NULL) return;
    cheatProgramFreeInsns(program);
    memset(program, 0, sizeof *program);
}

void nxusCheatReset(NxusCheatProgram *program) {
    NxusCheatInsn *insns;
    u32 capacity;
    NxusCheatFreeFn release;
    void *release_user;

    if (program == NULL) return;

    /* 命令配列は解放せず「空」にする（release の責務）。ここで free すると
       既存契約（reset 後の再 install で再利用できる）が変わり、呼び出し側が
       二重解放する危険も生まれる。 */
    insns = program->insns;
    capacity = program->insn_capacity;
    release = program->insns_free;
    release_user = program->insns_free_user;

    /* NxusCheatProgram は全部ゼロが「空・全部無効」を意味する。 */
    memset(program, 0, sizeof *program);

    program->insns = insns;
    program->insn_capacity = capacity;
    program->insns_free = release;
    program->insns_free_user = release_user;
}

/**
 * wire の 1 命令を読み出す。
 *
 * wire はパケットのペイロードで整列保証が無いため、packed 構造体へ
 * キャストせず memcpy でコピーする（未整列アクセス禁止）。
 */
static void cheatLoadInsn(const u8 *base, size_t offset, NxusCheatInsn *out) {
    memcpy(out, base + offset, sizeof *out);
}

static void cheatLoadBlock(const u8 *base, size_t offset, NxusCheatBlockDesc *out) {
    memcpy(out, base + offset, sizeof *out);
}

int nxusCheatInstall(NxusCheatProgram *program, const void *wire, size_t length) {
    const u8 *base = (const u8 *)wire;
    NxusCheatProgramHeader header;
    size_t block_offset;
    size_t insn_offset;
    size_t expected;
    u32 block_index;
    u32 insn_total;

    if (program == NULL || wire == NULL) return CHEAT_ERR_BAD_MAGIC;
    if (length < sizeof header) return CHEAT_ERR_BAD_SIZE;

    memcpy(&header, base, sizeof header);

    if (header.magic != NXUS_CHEATVM_MAGIC) return CHEAT_ERR_BAD_MAGIC;
    /* バージョン違いは「別のプログラム」として magic と同じ扱いにする:
       解釈が変わる可能性があるものを実行しない。 */
    if (header.version != NXUS_CHEATVM_VERSION) return CHEAT_ERR_BAD_MAGIC;

    if (header.block_count > NXUS_CHEATVM_MAX_BLOCKS) return CHEAT_ERR_BAD_BLOCK;
    if (header.insn_count > NXUS_CHEATVM_MAX_INSNS) return CHEAT_ERR_TOO_MANY;

    block_offset = sizeof header;
    insn_offset = block_offset + (size_t)header.block_count * sizeof(NxusCheatBlockDesc);
    expected = insn_offset + (size_t)header.insn_count * sizeof(NxusCheatInsn);

    /* total_bytes と実長の両方が一致しないと受け付けない（厳密）:
       片方だけ信じると、切り詰められたペイロードを「完全なプログラム」として
       実行してしまう。 */
    if ((size_t)header.total_bytes != expected) return CHEAT_ERR_BAD_SIZE;
    if (length != expected) return CHEAT_ERR_BAD_SIZE;
    if (expected > NXUS_CHEATVM_MAX_PROGRAM_BYTES) return CHEAT_ERR_BAD_SIZE;

    /* ---- ここから検証。program には一切書かない（失敗時に不変を保証する）----
       全ブロック・全命令を wire 上で読みながら検査し、全部通ってから確保・
       コピーする。検証のために NxusCheatProgram の一時コピーをスタックに
       置かないのは、実機のワーカースレッドのスタックを圧迫しないため。 */
    insn_total = header.insn_count;
    for (block_index = 0; block_index < header.block_count; block_index++) {
        NxusCheatBlockDesc block;
        u32 insn_index;

        cheatLoadBlock(base, block_offset + (size_t)block_index * sizeof block, &block);

        if (block.mode > 1) return CHEAT_ERR_BAD_BLOCK;
        /* 桁溢れしない形で first + count <= insn_count を検査する。 */
        if (block.count > insn_total || block.first > insn_total - block.count) {
            return CHEAT_ERR_BAD_BLOCK;
        }

        for (insn_index = 0; insn_index < block.count; insn_index++) {
            NxusCheatInsn insn;
            size_t offset = insn_offset + (size_t)(block.first + insn_index) * sizeof insn;

            cheatLoadInsn(base, offset, &insn);

            if ((u32)insn.op > (u32)NxusCheatOp_KeypressConditional) {
                return CHEAT_ERR_BAD_BLOCK; /* 未対応 opcode */
            }
            if (!cheatWidthOk(insn.width)) return CHEAT_ERR_BAD_BLOCK;
            if ((u32)insn.region > (u32)NxusCheatRegion_Absolute) {
                return CHEAT_ERR_BAD_BLOCK;
            }
            if (cheatIsBranch((u32)insn.op)) {
                /* 分岐先がブロック内に無い命令を指すと、実行時に別ブロックの
                   命令へ飛べてしまい、命令列の意味が壊れる。リンク済み IR で
                   ある以上ここで弾ける。 */
                if (insn.target < block.first || insn.target >= block.first + block.count) {
                    return CHEAT_ERR_BAD_TARGET;
                }
            }
        }
    }

    /* ---- 検証済み: 命令配列を必要分だけ確保する ----------------------
       確保が失敗したら program には一切触れない（直前のプログラムがそのまま
       残る）。旧バッファの解放は新しい確保が成功した後に行うので、失敗時に
       program を壊さず、再 install でリークもしない。 */
    {
        NxusCheatInsn *new_insns = NULL;
        u32 new_capacity = 0;

        if (header.insn_count > 0) {
            size_t bytes = (size_t)header.insn_count * sizeof(NxusCheatInsn);

            new_insns = g_cheat_alloc(bytes, g_cheat_alloc_user);
            if (new_insns == NULL) return NXUS_CHEATVM_ERR_NO_MEMORY;
            new_capacity = header.insn_count;
            memcpy(new_insns, base + insn_offset, bytes);
        }

        cheatProgramFreeInsns(program);
        program->insns = new_insns;
        program->insn_capacity = new_capacity;
        program->insns_free = g_cheat_free;
        program->insns_free_user = g_cheat_alloc_user;
    }

    /* ---- ここから program の残りを書き換える ------------------------- */
    program->header = header;
    memcpy(program->blocks, base + block_offset,
           (size_t)header.block_count * sizeof(NxusCheatBlockDesc));
    memset(program->blocks + header.block_count, 0,
           (NXUS_CHEATVM_MAX_BLOCKS - header.block_count) * sizeof(NxusCheatBlockDesc));

    /* 命令は確保済みのバッファへコピー済み。固定配列だった頃の末尾ゼロ埋めは
       不要（ヒープ配列は insn_count 分しか持たず、ブロック範囲はすべて
       insn_count 内であることを上で検証済み）。 */

    memset(program->state, 0, sizeof program->state);
    for (block_index = 0; block_index < header.block_count; block_index++) {
        /* wire の enabled はアップロード時の希望。patch ブロックも含めて
           次 tick で 1 回走らせるため ran_once は false のまま。 */
        program->state[block_index].enabled = program->blocks[block_index].enabled != 0;
        program->state[block_index].ran_once = false;
    }

    memset(program->registers, 0, sizeof program->registers);
    memset(program->saved_registers, 0, sizeof program->saved_registers);
    program->keys_held = 0;
    program->paused = false;
    program->tick_count = 0;
    return NXUS_CHEATVM_OK;
}

int nxusCheatSetEnabled(NxusCheatProgram *program, u32 index, bool enabled) {
    if (program == NULL) return NXUS_CHEATVM_ERR_BAD_PROGRAM;
    if (index >= NXUS_CHEATVM_MAX_BLOCKS) return NXUS_CHEATVM_ERR_BAD_BLOCK;
    if (index >= program->header.block_count) return NXUS_CHEATVM_ERR_BAD_BLOCK;

    program->state[index].enabled = enabled;
    /* patch ブロックをもう一度有効化したら、次の tick でまた 1 回走らせる。
       ここで ran_once を落とさないと「無効 → 有効」で二度目が走らない。 */
    program->state[index].ran_once = false;
    if (enabled) {
        program->state[index].last_error = 0;
        program->state[index].error_pc = 0;
    }
    /* 無効化は元バイトを書き戻さない。Panic Restore / 明示 Restore の担当で
       あり、勝手に戻すと :OFF コード（ブロック自身の解除手順）と二重になる。 */
    return NXUS_CHEATVM_OK;
}

/* ======================================================================== */
/* インタプリタ                                                             */
/* ======================================================================== */

/** ループ 1 段分。ネストは Atmosphere と同じく最大 16 段まで許す。 */
typedef struct CheatLoopFrame {
    u32 counter_register;
    u32 remaining;
    u32 start_pc; /* 対応する LoopStart の位置（再入判定に使う） */
} CheatLoopFrame;

#define CHEAT_MAX_LOOP_DEPTH 16u

/**
 * count == 0 のループで本体を飛ばすための「対応する LoopEnd の次」を探す。
 *
 * Rust 版は JumpInfo.loop_end を持っているが、この IR には無いので命令列を
 * 走査する（ブロックは最大 512 命令なので 1 回の線形走査で済む）。
 * 見つからなければブロック末尾＝何もしない、に倒す（安全側）。
 */
static u32 cheatSkipEmptyLoop(const NxusCheatProgram *program, u32 end, u32 start) {
    u32 depth = 1;
    u32 pc;

    for (pc = start + 1; pc < end; pc++) {
        NxusCheatInsn insn;
        memcpy(&insn, &program->insns[pc], sizeof insn);
        if ((u32)insn.op == (u32)NxusCheatOp_LoopStart) {
            depth++;
        } else if ((u32)insn.op == (u32)NxusCheatOp_LoopEnd) {
            depth--;
            if (depth == 0) return pc + 1;
        }
    }
    return end;
}

/**
 * 1 ブロックを実行する。失敗した命令のインデックスを *error_pc に残す
 * （Tick が state[].error_pc に記録するため）。
 *
 * 設計上の注意:
 *  - 汎用/退避レジスタはブロックごとにクリアする（Atmosphere の ResetState と
 *    Rust 版 reset_transient に合わせる）。前のブロックの値が漏れると、
 *    レジスタ相対のポインタチェーンが別ブロックのせいで壊れる。
 *  - 命令数は NXUS_CHEATVM_STEP_LIMIT で打ち切る。壊れたループで 16 ms
 *    ワーカーが固まると、サーバ全体（読み書き・切断処理）が止まる。
 */
static int cheatRunBlock(NxusCheatProgram *program, u32 index, const NxusCheatIo *io,
                         u64 keys_held, NxusCheatJournal *journal, u32 *error_pc) {
    CheatLoopFrame frames[CHEAT_MAX_LOOP_DEPTH];
    NxusCheatBlockDesc block;
    u32 depth = 0;
    u32 end;
    u32 pc;
    u32 steps = 0;

    memcpy(&block, &program->blocks[index], sizeof block);
    end = block.first + block.count;
    pc = block.first;

    memset(program->registers, 0, sizeof program->registers);
    memset(program->saved_registers, 0, sizeof program->saved_registers);
    program->keys_held = keys_held;

    while (pc < end) {
        NxusCheatInsn insn;
        int rc;

        if (steps >= NXUS_CHEATVM_STEP_LIMIT) {
            *error_pc = pc;
            return NXUS_CHEATVM_ERR_STEP_LIMIT;
        }
        steps++;

        /* 命令の読み出しも memcpy（program->insns は packed で、将来
           未整列な置き方をしても壊れないようにする）。 */
        memcpy(&insn, &program->insns[pc], sizeof insn);

        switch ((u32)insn.op) {
            case (u32)NxusCheatOp_Nop:
                pc++;
                break;

            case (u32)NxusCheatOp_StoreStatic: {
                u64 offset = 0;
                u64 address;

                if ((insn.flags & 1u) != 0) {
                    if (insn.reg_b >= 16) { *error_pc = pc; return NXUS_CHEATVM_ERR_BAD_REGISTER; }
                    offset = program->registers[insn.reg_b];
                }
                address = cheatResolve(insn.region, insn.address, offset);
                rc = cheatWriteValue(io, journal, address, insn.width,
                                     cheatTruncate(insn.value, insn.width), (u8)index);
                if (rc != NXUS_CHEATVM_OK) { *error_pc = pc; return rc; }
                pc++;
                break;
            }

            case (u32)NxusCheatOp_BeginConditional: {
                u64 offset = 0;
                u64 address;
                u64 source = 0;
                u64 expected;
                bool condition;

                if (insn.cmp > (u32)NxusCheatCmp_NotEqual) {
                    *error_pc = pc;
                    return NXUS_CHEATVM_ERR_BAD_OPCODE;
                }
                if ((insn.flags & 1u) != 0) {
                    if (insn.reg_b >= 16) { *error_pc = pc; return NXUS_CHEATVM_ERR_BAD_REGISTER; }
                    offset = program->registers[insn.reg_b];
                }
                address = cheatResolve(insn.region, insn.address, offset);
                rc = cheatReadValue(io, address, insn.width, &source);
                if (rc != NXUS_CHEATVM_OK) { *error_pc = pc; return rc; }
                expected = cheatTruncate(insn.value, insn.width);
                condition = cheatCompare(insn.cmp, source, expected);
                pc = condition ? pc + 1 : insn.target;
                break;
            }

            case (u32)NxusCheatOp_Else:
                /* 条件が真だったとき、else 本体を飛ばして EndConditional の次へ。 */
                pc = insn.target;
                break;

            case (u32)NxusCheatOp_EndConditional:
                pc++;
                break;

            case (u32)NxusCheatOp_LoopStart: {
                u32 count = (u32)insn.value;

                if (insn.reg_a >= 16) { *error_pc = pc; return NXUS_CHEATVM_ERR_BAD_REGISTER; }

                /* 再入判定: LoopEnd は target（= この LoopStart）へ戻る。そのまま
                   「rA = value とカウンタ設定」をやり直すとカウンタが毎回
                   リセットされ、ループが永久に終わらない。直前に積んだフレームが
                   この命令のものなら、カウンタを維持して本体へ進む。 */
                if (depth > 0 && frames[depth - 1].start_pc == pc) {
                    pc++;
                    break;
                }

                if (count == 0) {
                    /* 0 回ループ。Atmosphere だと終端でアンダーフローするので、
                       Rust 版と同じく本体を丸ごと飛ばす。 */
                    pc = cheatSkipEmptyLoop(program, end, pc);
                    break;
                }
                if (depth >= CHEAT_MAX_LOOP_DEPTH) {
                    *error_pc = pc;
                    return NXUS_CHEATVM_ERR_BAD_OPCODE;
                }
                program->registers[insn.reg_a] = count;
                frames[depth].counter_register = insn.reg_a;
                frames[depth].remaining = count;
                frames[depth].start_pc = pc;
                depth++;
                /* 本体は次の命令から。LoopStart の target は「本体の先頭」を
                   指す情報でしかないので、ここでは使わない（リンク済み IR でも
                   必ず pc+1 になる）。 */
                pc++;
                break;
            }

            case (u32)NxusCheatOp_LoopEnd: {
                CheatLoopFrame *frame;

                if (insn.reg_a >= 16) { *error_pc = pc; return NXUS_CHEATVM_ERR_BAD_REGISTER; }
                if (depth == 0) { *error_pc = pc; return NXUS_CHEATVM_ERR_BAD_OPCODE; }
                frame = &frames[depth - 1];
                if (frame->counter_register != insn.reg_a) {
                    /* 対応する LoopStart とレジスタが違うのはリンクミス。
                       そのまま回すとカウンタが 0 のまま無限ループになる。 */
                    *error_pc = pc;
                    return NXUS_CHEATVM_ERR_BAD_OPCODE;
                }
                if (frame->remaining > 0) frame->remaining--;
                program->registers[insn.reg_a] = frame->remaining;
                if (frame->remaining == 0) {
                    depth--;
                    pc++;
                } else {
                    if (insn.target >= end || insn.target < block.first) {
                        *error_pc = pc;
                        return NXUS_CHEATVM_ERR_BAD_TARGET;
                    }
                    pc = insn.target;
                }
                break;
            }

            case (u32)NxusCheatOp_LoadRegImm:
                if (insn.reg_a >= 16) { *error_pc = pc; return NXUS_CHEATVM_ERR_BAD_REGISTER; }
                program->registers[insn.reg_a] = (u32)cheatTruncate(insn.value, 4);
                pc++;
                break;

            case (u32)NxusCheatOp_LoadRegMem: {
                u64 offset = 0;
                u64 address;
                u64 value = 0;

                if (insn.reg_a >= 16) { *error_pc = pc; return NXUS_CHEATVM_ERR_BAD_REGISTER; }
                if ((insn.flags & 1u) != 0) {
                    if (insn.reg_b >= 16) { *error_pc = pc; return NXUS_CHEATVM_ERR_BAD_REGISTER; }
                    offset = program->registers[insn.reg_b];
                }
                address = cheatResolve(insn.region, insn.address, offset);
                rc = cheatReadValue(io, address, insn.width, &value);
                if (rc != NXUS_CHEATVM_OK) { *error_pc = pc; return rc; }
                program->registers[insn.reg_a] = (u32)value;
                pc++;
                break;
            }

            case (u32)NxusCheatOp_StoreStaticToReg: {
                u64 address;

                if (insn.reg_a >= 16) { *error_pc = pc; return NXUS_CHEATVM_ERR_BAD_REGISTER; }
                address = program->registers[insn.reg_a];
                if ((insn.flags & 1u) != 0) {
                    if (insn.reg_b >= 16) { *error_pc = pc; return NXUS_CHEATVM_ERR_BAD_REGISTER; }
                    address += program->registers[insn.reg_b];
                }
                rc = cheatWriteValue(io, journal, address, insn.width,
                                     cheatTruncate(insn.value, insn.width), (u8)index);
                if (rc != NXUS_CHEATVM_OK) { *error_pc = pc; return rc; }
                if ((insn.flags & 2u) != 0) {
                    /* Atmosphere の 6T0RIor0 の I ビット: 書いた幅だけ進める。 */
                    program->registers[insn.reg_a] += insn.width;
                }
                pc++;
                break;
            }

            case (u32)NxusCheatOp_ArithImm:
                if (insn.reg_a >= 16) { *error_pc = pc; return NXUS_CHEATVM_ERR_BAD_REGISTER; }
                if (insn.cmp > (u32)NxusCheatArith_Rsh) {
                    *error_pc = pc;
                    return NXUS_CHEATVM_ERR_BAD_OPCODE;
                }
                /* Rust 版と同じく、被演算数を切り詰めるのは結果だけ
                   （0xFF + 0x10 を幅 1 に丸めて 0x0F にする）。 */
                program->registers[insn.reg_a] =
                    (u32)cheatTruncate(cheatArith(insn.cmp, program->registers[insn.reg_a],
                                                  insn.value),
                                       insn.width);
                pc++;
                break;

            case (u32)NxusCheatOp_LoadRegMemReg: {
                u64 address;
                u64 value = 0;

                if (insn.reg_a >= 16) { *error_pc = pc; return NXUS_CHEATVM_ERR_BAD_REGISTER; }
                address = (u64)program->registers[insn.reg_a] + (u64)insn.address;
                rc = cheatReadValue(io, address, insn.width, &value);
                if (rc != NXUS_CHEATVM_OK) { *error_pc = pc; return rc; }
                program->registers[insn.reg_a] = (u32)value;
                pc++;
                break;
            }

            case (u32)NxusCheatOp_LoadRegMemRegReg: {
                u64 address;
                u64 value = 0;

                if (insn.reg_a >= 16 || insn.reg_b >= 16) {
                    *error_pc = pc;
                    return NXUS_CHEATVM_ERR_BAD_REGISTER;
                }
                address = (u64)program->registers[insn.reg_a] +
                          (u64)program->registers[insn.reg_b];
                rc = cheatReadValue(io, address, insn.width, &value);
                if (rc != NXUS_CHEATVM_OK) { *error_pc = pc; return rc; }
                program->registers[insn.reg_a] = (u32)value;
                pc++;
                break;
            }

            case (u32)NxusCheatOp_LoadRegMemRegRegion: {
                u64 address;
                u64 value = 0;

                if (insn.reg_a >= 16) { *error_pc = pc; return NXUS_CHEATVM_ERR_BAD_REGISTER; }
                address = cheatResolve(insn.region, program->registers[insn.reg_a], insn.address);
                rc = cheatReadValue(io, address, insn.width, &value);
                if (rc != NXUS_CHEATVM_OK) { *error_pc = pc; return rc; }
                program->registers[insn.reg_a] = (u32)value;
                pc++;
                break;
            }

            case (u32)NxusCheatOp_ArithReg:
                if (insn.reg_a >= 16 || insn.reg_b >= 16) {
                    *error_pc = pc;
                    return NXUS_CHEATVM_ERR_BAD_REGISTER;
                }
                if (insn.cmp > (u32)NxusCheatArith_Rsh) {
                    *error_pc = pc;
                    return NXUS_CHEATVM_ERR_BAD_OPCODE;
                }
                program->registers[insn.reg_a] =
                    (u32)cheatTruncate(cheatArith(insn.cmp, program->registers[insn.reg_a],
                                                  program->registers[insn.reg_b]),
                                       insn.width);
                pc++;
                break;

            case (u32)NxusCheatOp_StoreReg:
                if (insn.reg_a >= 16 || insn.reg_b >= 16) {
                    *error_pc = pc;
                    return NXUS_CHEATVM_ERR_BAD_REGISTER;
                }
                rc = cheatWriteValue(io, journal, (u64)program->registers[insn.reg_a], insn.width,
                                     cheatTruncate(program->registers[insn.reg_b], insn.width),
                                     (u8)index);
                if (rc != NXUS_CHEATVM_OK) { *error_pc = pc; return rc; }
                pc++;
                break;

            case (u32)NxusCheatOp_RegConditional: {
                u64 source;
                u64 other;
                bool condition;

                if (insn.reg_a >= 16) { *error_pc = pc; return NXUS_CHEATVM_ERR_BAD_REGISTER; }
                if (insn.cmp > (u32)NxusCheatCmp_NotEqual) {
                    *error_pc = pc;
                    return NXUS_CHEATVM_ERR_BAD_OPCODE;
                }
                if ((insn.flags & 1u) != 0) {
                    if (insn.reg_b >= 16) { *error_pc = pc; return NXUS_CHEATVM_ERR_BAD_REGISTER; }
                    other = cheatTruncate(program->registers[insn.reg_b], insn.width);
                } else {
                    other = cheatTruncate(insn.value, insn.width);
                }
                source = cheatTruncate(program->registers[insn.reg_a], insn.width);
                condition = cheatCompare(insn.cmp, source, other);
                pc = condition ? pc + 1 : insn.target;
                break;
            }

            case (u32)NxusCheatOp_SaveRegs: {
                u32 mask = (u32)insn.value & 0xFFFFu;
                u32 reg;
                for (reg = 0; reg < 16; reg++) {
                    if ((mask & (1u << reg)) != 0) {
                        program->saved_registers[reg] = program->registers[reg];
                    }
                }
                pc++;
                break;
            }

            case (u32)NxusCheatOp_RestoreRegs: {
                u32 mask = (u32)insn.value & 0xFFFFu;
                u32 reg;
                for (reg = 0; reg < 16; reg++) {
                    if ((mask & (1u << reg)) != 0) {
                        program->registers[reg] = program->saved_registers[reg];
                    }
                }
                pc++;
                break;
            }

            case (u32)NxusCheatOp_StaticRegs:
                /* 予約（静的レジスタブロック）。この IR では未使用なので
                   Nop と同じ扱いにする: 未対応で止めるより、前後の命令を
                   実行したほうが害が小さい。 */
                pc++;
                break;

            case (u32)NxusCheatOp_Pause:
                /* 0xFF0: このブロックの残りを打ち切る。pc を保存しないので
                   次の tick は先頭から（要件どおり）。 */
                program->paused = true;
                return NXUS_CHEATVM_OK;

            case (u32)NxusCheatOp_Resume:
                program->paused = false;
                pc++;
                break;

            case (u32)NxusCheatOp_KeypressConditional:
                /* 全ビット AND: マスクのビットが 1 つでも欠けたら不成立。
                   部分一致で発動すると、コンボの取りこぼしで意図しない
                   タイミングにチートが効く。 */
                if ((insn.value & keys_held) == insn.value) {
                    pc++;
                } else {
                    pc = insn.target;
                }
                break;

            default:
                *error_pc = pc;
                return NXUS_CHEATVM_ERR_BAD_OPCODE;
        }
    }

    return NXUS_CHEATVM_OK;
}

int nxusCheatRunBlock(NxusCheatProgram *program, u32 index, const NxusCheatIo *io, u64 keys_held,
                      NxusCheatJournal *journal) {
    u32 error_pc = 0;

    if (program == NULL) return NXUS_CHEATVM_ERR_BAD_PROGRAM;
    if (io == NULL || io->read == NULL || io->write == NULL) return NXUS_CHEATVM_ERR_BAD_PROGRAM;
    if (index >= NXUS_CHEATVM_MAX_BLOCKS || index >= program->header.block_count) {
        return NXUS_CHEATVM_ERR_BAD_BLOCK;
    }
    return cheatRunBlock(program, index, io, keys_held, journal, &error_pc);
}

u32 nxusCheatTick(NxusCheatProgram *program, const NxusCheatIo *io, u64 keys_held,
                  NxusCheatJournal *journal) {
    u32 block_count;
    u32 index;
    u32 ran = 0;

    if (program == NULL || io == NULL || io->read == NULL || io->write == NULL) return 0;

    program->keys_held = keys_held;
    block_count = program->header.block_count;
    if (block_count > NXUS_CHEATVM_MAX_BLOCKS) block_count = NXUS_CHEATVM_MAX_BLOCKS;

    for (index = 0; index < block_count; index++) {
        NxusCheatBlockState *state = &program->state[index];
        NxusCheatBlockDesc block;
        u32 error_pc = 0;
        int rc;

        if (!state->enabled) continue;

        memcpy(&block, &program->blocks[index], sizeof block);
        /* patch ブロックは有効化後 1 回だけ。loop は毎 tick。 */
        if (block.mode == 0 && state->ran_once) continue;

        /* ジャーナルは tick 中ずっと同じ 1 本。ここで渡し切るので、
           「run now」と tick が入れ子になっても取り違えない。 */
        rc = cheatRunBlock(program, index, io, keys_held, journal, &error_pc);
        ran++;
        state->execs++;

        if (rc == NXUS_CHEATVM_OK) {
            if (block.mode == 0) state->ran_once = true;
            /* 直近の実行が成功したので、前回の失敗は「復旧済み」として消す。
               patch ブロックが 1 回失敗した場合も ran_once はまだ false なので
               次の tick で再試行できる（一時的な読み失敗から自動回復する）。 */
            state->last_error = 0;
            state->error_pc = 0;
        } else {
            /* 1 つのブロックの失敗で他を止めない: 失敗はここに記録し、
               次のブロックへ進む。 */
            state->last_error = (u32)rc;
            state->error_pc = error_pc;
        }
    }

    program->tick_count++;
    return ran;
}