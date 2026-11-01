# Nxus-ox 引き継ぎ書（エージェント向け / 完全版）

最終更新: 2026-11-01
対象: `C:\anyWorkspace\nx\Nxus` / branch `main` / HEAD `main` の最新コミット（`git rev-parse --short HEAD` で確認） / tag `v0.1.0-alpha`
読み手: このプロジェクトを引き継いで「レビュー → 修正 → レビュー」を回すエージェント

---

## 0. 30 秒サマリ

- **Nxus-ox** = Nintendo Switch（Atmosphère CFW）向けの**常駐 sysmodule** ＋ Windows 用**統合 PC クライアント**（`nxus.exe` 1 本で GUI と CLI の両方）。
- 機能: リモートメモリスキャン（初回・絞り込み・型変換）、ポインタスキャン、ハードウェアウォッチポイント/ブレークポイント、レジスタ表示/変更、逆アセンブル、コードパッチ、アドレス凍結、スナップショット差分、チートコード生成、RAM ダンプ（Jnoexs NDMP / EdiZon-SE EDZN）相互変換。
- リポジトリ: `C:\anyWorkspace\nx\Nxus`（remote: `https://github.com/Nexy451z/Nxus-ox.git`）
- 実機: **`192.168.1.13`**（FTP `:5000` 匿名 / NxusTCP `7332`）
- **最重要の運用制約: sysmodule は起動時にしかロードされない。`exefs.nsp` を入れ替えたら必ず本体を再起動。** レポートでは毎回「要再起動」と明記する。
- 検証（ハードウェア不要）: ホスト C **1,937 checks / 9 binaries**、Rust **124**、Python E2E **122**。

---

## 1. これは何か（プロダクト像）

| 項目 | 内容 |
|---|---|
| 目的 | PC から Wi-Fi 経由で Switch のゲームメモリを解析・デバッグする。数 GB の RAM ダンプ転送を不要にする「オンデバイススキャン」が売り |
| 対象 | Atmosphère 上の任意タイトル（32bit/AArch32・64bit/AArch64 両対応） |
| sysmodule タイトルID | `0x4200000000004E58` = nxus（本体）, `0x4200000000004E59` = probe（診断用・既定では boot2.flag なし） |
| 配布 | GitHub Release `v0.1.0-alpha`（atmosphere zip / probe zip / windows-x64 zip / nxus.exe 単体） |
| ライセンス/免責 | 無保証。Alpha |
| 主な実機検証タイトル | MHXX（`0100C3800049C000`、AArch32、固定レイアウト気味） |

### 絶対に守る安全原則
1. **probe と nxus を同時に boot しない**（同じ dmnt cheat process を取り合う）。probe zip には `DO_NOT_BOOT_TOGETHER.txt` を同梱し、boot2.flag を入れない。
2. 対象プロセスの所有権チェックを緩めない（後述の identity / incarnation / mapping generation）。
3. 8 MiB の sysmodule ヒープ予算を超えない（後述）。

---

## 2. 現在の状態スナップショット

```
HEAD        main の最新コミット（レビュー&修正ラウンド後。ハッシュは `git rev-parse --short HEAD`）
tag         v0.1.0-alpha (force-updated each release)
branch      main (origin/main と同期・作業ツリー clean)
dist        dist/atmosphere/contents/4200000000004E58/exefs.nsp  193,725 B
            dist/atmosphere/contents/4200000000004E59/exefs.nsp  110,206 B
            dist/pc/nxus.exe
metadata    source_rev = HEAD, dirty = false （dist を HEAD で再ビルド済み）
実機 SD     4E58 = 193,725 B（最新と sha1 一致・転送済み）
```

### テスト数（README と一致していること）
| スイート | コマンド | 数 |
|---|---|---|
| ホスト C | `bash tests/run_tests.sh` | **1,937 checks / 9 binaries**（scan 797, ptrscan 45, snapshot 75, budget 63, scantypes 275, hotkey 11, server_logic 150, session_view 313, snapshot_owner 208） |
| Rust | `cd pc/Nxus.Cli && cargo test` | **124** |
| Python E2E | `cd pc && python -m unittest discover -s tests` | **122**（MockSwitch 相手） |

---

## 3. リポジトリ構成

```
Nxus/
├─ README.md                     ← 本体ドキュメント（利用者向け・ここが正）
├─ docs/                         ← 補助ドキュメント（下記 15 章）
├─ core/                         ← Switch/PC 共有の純粋ロジック（ハード非依存・ホストテスト対象）
│   ├─ nxus_protocol.h           ★ ワイヤ仕様の唯一の正（構造体・コマンド・理由コード）
│   ├─ nxus_scan.c/.h            スキャンエンジン（SoA ヒット配列・ベースライン・比較）
│   ├─ nxus_ptrscan.c/.h         ポインタスキャンエンジン（幅自動判定・memo/dead_set）
│   ├─ nxus_hotkey.c/.h          ホットキー解析
│   └─ nxus_hash.c/.h            ブロックハッシュ
├─ shared/                       ← sysmodule 側の共有ユーティリティ（libnx 依存）
│   ├─ nxus_net.c/.h             TCP サーバ（受信/送信/キープアライブ/終了）
│   ├─ nxus_dmntcht.c/.h         dmnt:cheat ラッパ（metadata/read/write/freeze/incarnation）
│   ├─ nxus_log.c/.h             SD ログ＋リングバッファ（終端ラッチあり）
│   └─ nxus_hid.c/.h             ホットキー入力スレッド
├─ switch/                       ← sysmodule 本体
│   ├─ source/main.c             起動順・ヒープ・__appExit・ビルドID
│   ├─ source/nxus_server.c      ★ コマンドディスパッチ・スキャン/ptrscan/凍結/終了処理
│   ├─ source/nxus_session.c     ★ マッピング/リージョン seqlock・ヒット所有権・スキャンワーカー
│   ├─ source/nxus_debug.c       ★ カーネルデバッガ（attach/detach/BKP/WP/step）
│   ├─ source/nxus_snapshot_srv.c スナップショット 2 スロット・差分
│   ├─ include/*.h               公開 API
│   └─ nxus.json                 NPDM テンプレート（allow_debug のみ。ForceDebug はビルド後 patch）
├─ probe/                        ← 診断用 sysmodule（タイトル 4E59）
├─ pc/Nxus.Cli/                  ← Rust クライアント
│   └─ src/{main,cli,client,protocol,gui/*,pcscan,dump,edizon}.rs
├─ pc/nxus/                      ← Python 参照実装（テスト用）
│   ├─ client.py, protocol.py, mock_switch.py
├─ pc/tests/                     ← Python E2E（MockSwitch 相手）
├─ tests/                        ← ホスト C テスト（9 バイナリ）＋ stubs/
├─ tools/                        ← build.sh / verify_artifact.py / pfs0_tool.py 他
├─ release_packages/             ← _make_packages.py と生成 zip（gitignored）
└─ dist/                         ← ビルド成果物（gitignored）
```

サイズ感（行数、**非空行**）: `nxus_server.c` 約 4,200 / `gui/mod.rs` 約 3,270 / `protocol.rs` 約 2,930 / `cli.rs` 約 2,750 / `nxus_session.c` 約 2,530 / `nxus_debug.c` 約 2,360。合計 約 46,600 行（C/Rust/Python/Shell）。

---

## 4. ビルド

### 前提
- devkitPro: `C:\devkitPro`（devkitA64 + libnx + msys2 bash）
- Rust: stable（`cargo`）
- Python: 3.12
- bash は `C:\devkitPro\msys2\usr\bin\bash.exe` を使う（PowerShell から呼ぶ）

### Switch sysmodule（nxus + probe）
```powershell
cd C:\anyWorkspace\nx\Nxus
& "C:\devkitPro\msys2\usr\bin\bash.exe" -lc "cd /c/anyWorkspace/nx/Nxus && make -C switch clean && bash tools/build.sh"
```
- `tools/build.sh` がやること: NSO/PFS0 パック → NPDM 生成（`tools/npdm_debug_patch.py` で ForceDebug ビット）→ `dist/atmosphere/contents/<TID>/exefs.nsp` → README.txt/metadata.json 生成 → **最後に `tools/verify_artifact.py`**。
- probe を boot2 付きで検証したいときだけ: `NXUS_STAGE_PROBE=1 bash tools/build.sh`（nxus 側は flag なし、probe 側に flag。混在させない）。
- 警告 0 / エラー 0 / `verify_artifact.py` FAIL 0 を確認する。WARN は `.bss` + stack が 8 MiB を超え、かつ `system_resource_size=0` のとき 1 件出るのが既知（現在の要求量は 8.44 MiB）。

### PC クライアント
```powershell
cd C:\anyWorkspace\nx\Nxus\pc
cargo build --release --manifest-path Nxus.Cli\Cargo.toml
Copy-Item Nxus.Cli\target\release\nxus.exe ..\dist\pc\nxus.exe -Force
```

---

## 5. テスト

```powershell
# 1) ホスト C（9 バイナリ / 1,937 checks）
& "C:\devkitPro\msys2\usr\bin\bash.exe" -lc "cd /c/anyWorkspace/nx/Nxus/tests && bash run_tests.sh"

# 2) Rust（124）
cd C:\anyWorkspace\nx\Nxus\pc; cargo test --release --manifest-path Nxus.Cli\Cargo.toml

# 3) Python E2E（122・MockSwitch）
cd C:\anyWorkspace\nx\Nxus\pc; python -m unittest discover -s tests
```

### 重要な注意
- **Python E2E は exe の鮮度ガードを持つ**: `pc/Nxus.Cli/target/release/nxus.exe` が `.rs` より古いと `AssertionError: nxus.exe is older than the newest .rs source`。**コードを触ったら必ず先に cargo build**。
- ホスト C テストは `tests/stubs/` のスタブで実ソースを include/コンパイルする。新しいシンボルを sysmodule 側に足したら**スタブにも足す**（例: `nxusDmntTargetIncarnation`, `nxusDmntAdoptNextOpen`）。忘れると `test_snapshot_owner` がリンクエラー。
- `tests/run_tests.sh` は 9 バイナリを順にビルド＆実行。失敗時は `tests/<name>.build.log` を見る。
- テストを追加したら **README の数値（合計と内訳）を必ず更新**する。数値は「実測」であること。

---

## 6. 実機（コンソール）

| 項目 | 値 |
|---|---|
| 本体 IP | `192.168.1.13` |
| FTP | `:5000` 匿名（`/atmosphere/contents/<TID>/`） |
| Nxus TCP | `7332` |
| nxus TID | `4200000000004E58` |
| probe TID | `4200000000004E59`（既定で boot2.flag なし） |

### SD への転送（PowerShell + Python）
```powershell
python -c "
import ftplib, io, os
for tid in ('4200000000004E58','4200000000004E59'):
    base = rf'C:\anyWorkspace\nx\Nxus\dist\atmosphere\contents\{tid}'
    ftp = ftplib.FTP(); ftp.connect('192.168.1.13', 5000, timeout=60); ftp.login()
    for name in ['exefs.nsp','README.txt','metadata.json'] + (['DO_NOT_BOOT_TOGETHER.txt'] if tid.endswith('4E59') else []):
        data = open(os.path.join(base, name),'rb').read()
        remote = f'/atmosphere/contents/{tid}/{name}'
        ftp.storbinary('STOR '+remote, io.BytesIO(data))
        buf = io.BytesIO(); ftp.retrbinary('RETR '+remote, buf.write)
        print(f'{tid[-4:]}/{name:24s} {len(data):7d} B match={buf.getvalue()==data}')
    ftp.quit()
"
```
（必ず読み戻して `match=True` を確認する。1 回タイムアウトしても `Test-NetConnection 192.168.1.13 -Port 5000` で疎通確認して再試行すれば通る。）

### 実機検証の基本手順
```powershell
cd C:\anyWorkspace\nx\Nxus\dist\pc
.\nxus.exe --host 192.168.1.13 status
.\nxus.exe --host 192.168.1.13 metadata
# 新ビルド確認: ログに "boot ok: ... build <日付>" と "dmnt: target incarnation N" が出る
.\nxus.exe --host 192.168.1.13 log | Select-String -Pattern "boot ok|incarnation"
```
- **新ビルドが動いているかの判定**: ①ログの `build <date>` ②`dmnt: target incarnation` 行の有無 ③行動で判定（例: 空リストへの `scan refine` が `0x8003C806` = 自前 BAD_STATE なら新、`0x00001759` = libnx BadInput なら旧）。
- MHXX での既知の値: 所持金 `9997199` → ヒットは 2 件（表示用コピーと実値）。1 件は `0x61774BD4` 近辺、もう 1 件はヒープ内 `0x6A2F5DC4`（起動ごとに変わる）。

### 実機でハマる点
- `metadata` が `0x0032C80D`（`CheatNotAttached`）で失敗する → dmnt の cheat process が未オープン。`scan begin` や `metadata` を呼べば開く（`status` は**状態を変えない**設計なので開かない）。
- 起動直後の `status` は `pid 0` になり得る（dmnt 未オープンのため）。スキャン後は埋まる。
- 実機で `scan refine <値>` が 0 件になる → 旧 PC クライアントの既定比較バグ（後述 12 章）。最新 `nxus.exe` を使う。

---

## 7. プロトコル（`core/nxus_protocol.h` が唯一の正）

### パケット
```c
typedef struct NXUS_PACKED {
    u32 magic;    // 0x4E585553 'NXUS'
    u16 type;     // NxusCmd_* / NxusEvent_*
    u16 flags;    // ASYNC 0x1 / ERROR 0x2 / MORE 0x4
    u32 length;   // payload bytes
    u32 seq;      // correlation id (0 for async)
} NxusPacketHeader;   // 16 B
```
- 既定ポート **7332**、magic `NXUS`。
- エラー応答の payload は `s32 Result` ＋ 任意で `u32 reason`（`error_reason_text()` が 1..13 を人間可読に）。
- **結果コードの 2 系統に注意**（12 章の罠）: 自前は `0x80000000 | (484 << 9) | (desc & 0x1FF)`。484 は HOS の **description フィールド（bit 9-17）** に入り、`desc` は **module フィールド（bit 0-8）** に入る（libnx の `R_MODULE()` は 484 ではなく `desc` を返す）。libnx は **bit31 を立てない** `(345) | (desc << 9)`。

### 主要コマンド（抜粋）
| 番号 | 名前 | 備考 |
|---|---|---|
| `0x0000` | Nop | 終端ゲート後も通る唯一のコマンド（生存確認） |
| `0x0004/0x0005` | GetStatus / GetMetadata | status は**読み取り専用**（dmnt を開かない） |
| `0x0013/0x0014` | Read / Write | 1 MiB 上限（`read limit`） |
| `0x0020/0x0021` | ScanBegin / ScanNext | 非同期ワーカー。`Running` 中は BUSY |
| `0x0030` 以降 | PtrScanBegin/Get | 非同期。開始応答は `NXUS_RESULT_PTRSCAN_STARTED = 0x8003C808` |
| `0x0041/0x0042` | FrozenEnable / Disable | サーバ側凍結 |
| `0x005C` | DebugStep | GDB 風ステップ |
| `0x0072` | SnapshotRelease | 2 スロットの解放 |
| `0x8008/0x8009` | Event DebugStopped / FrozenReleased | 非同期イベント |

### 互換ルール（壊すと既存 PC が誤動作する）
- **構造体は末尾追加のみ**。フレーム長で新旧を判定できるようにする（例: `NxusPtrChainListHeader` 16→20 B、`NxusDebugStatus` 32→40 B は length で判別）。
- 追加したもの: `NXUS_HITBATCH_DROPPED 0x0002`、`NxusEvent_FrozenReleased 0x8009`（payload `{u32 count; u32 reserved; u64 addresses[]}`、**配列は最大 32 件・count は総数**）、`NXUS_REASON_HEAP_BUDGET/DEBUG_LOCKED/SLOT_FULL/RETRY_LATER`（10..13）。
- `core/nxus_protocol.h` の `NXUS_STATIC_ASSERT` が Rust/Python のパリティテストを駆動している。**サイズを変えたらテストも直す**。

---

## 8. 設計上の要点（触る前に必ず読む）

### 8.1 ヒープ（8 MiB が絶対上限）
- `switch/source/main.c` の `INNER_HEAP_SIZE` = **8 MiB**。実測 `.bss` = **8.41 MiB**（`verify_artifact.py` の値）、stack `0x8000` を足した**常駐要求は 8.44 MiB**。`system_resource_size = 0` かつ `.bss` + stack > 8 MiB のため現状は WARN のみ（System プール依存）。16 MiB 超で FAIL。
- 内訳の目安: persistent 約 1.5 MB / スナップショット 2 スロット（256 KB×2） / ヒット配列（u32 で 150k 件 = 3.0 MB、u64 は 128k 件） / スキャン作業（chunk+window 約 1 MB） / ptrscan（scratch+regions+chains 約 1 MB）。
- `nxusSessionHitLimit()` は **`min(150k, 予算/(16+値幅))`**。ヒット 1 件は `NxusHitAddress` 16 B ＋ 値。**floor で予算を超えない**。
- `estimateHeapPeak()` は `sizeof(NxusHitAddress)` を使う（8 B 固定に戻すと 1.2 MB 過小評価）。

### 8.2 所有権（stale データを返さないための 3 点セット）
1. **identity**: `pid` / `program_id` / `main_base` / `generation` を seqlock で publish。
2. **mapping generation**: マッピング表の**内容フィンガープリント（count + (base,size) の混成）が変わったときだけ**インクリメント。毎回インクリメントするとスキャン直後の refine が誤って落ちる。
3. **incarnation**: dmnt が**新しいプロセスを開いたとき**だけ +1（`nxusDmntForceOpen` 成功かつ未オープン）。**debug の detach が同一プロセスを開き直す場合は `nxusDmntAdoptNextOpen()` で引き継ぐ**。ラッチは 1 回限りで、失敗/no-op 時は必ずクリア（残すと次プロセスのステイル判定が全滅する）。

ヒットは `NxusHitAddress{u32 offset; u16 mapping_idx; u16 reserved(=値型); u64 address;}` の 16 B（packed）。**絶対アドレスを持つ**ので、写像再構築時は `nxusSessionHitsRevalidate()` がアドレスで二分探索して `mapping_idx`/`offset` を書き直し、解決できないヒットだけ落とす（全滅時のみ `BAD_STATE`）。
- 救済は**同一 incarnation のみ**。
- 境界は `offset + value_size <= size` まで検証（跨ぎヒットは落とす）。

frozen / snapshot も incarnation 付きで所有権スタンプを持つ。

### 8.3 並行性
- **seqlock**: writer は `even bump(release)` → データ → `atomic_thread_fence(release)` → `odd bump` … ではなく実装は `viewUpdateBegin/End`。reader は `seq(acquire) → copy → fence(acquire) → 再確認`。**フェンスを外すと arm64 で torn read（OOB の恐れ）**。x86 のホストテストでは再現しないので注意。
- **スキャンワーカー**: `g_ScanThreadClaim` で join/close を 1 本化。`nxusSessionExit` / `ScanBegin` / `Reset` の**破壊的処理はすべて claim 保持下**。claim が取れない exit は**解放せずリーク**（UAF より安全）。
- **ptrscan ワーカー**: 同様に claim。90 秒の時間予算（`NXUS_PTRSCAN_TIME_BUDGET_MS`）、`max_reads = 0`（無制限＝時計のみ）、鎖は最大 128 件。読みは **4 KB ページキャッシュ（8 スロット=32 KB .bss）**経由、写像端はクランプし、はみ出しはゼロ埋め（窓全体を失敗させると dead-end メモ化で恒久的に誤否定になる）。
- **debug**: teardown claim（owner=Thread ハンドル＋再入深度）で attach/detach/exit を直列化。`g_DebugOpUsers` で全コマンドをガード。detach は 2 段ドレイン（500 ms + 1500 ms）→ `g_Debug = INVALID_HANDLE` 公開 → close。**close は 1 回だけ**。
- **終了**: `g_ServerExited`（atomic, seq_cst）で全コマンド（Nop 以外）と tick を拒否 → ptrscan cancel/join → **in-flight ハンドラを最大 3 秒 drain** → その後に session/snapshot/frozen を解放。3 秒で 0 にならなければ**解放しない**。
- **ログ**: 終端ラッチ（`g_LogFinal`）で `nxusLogExit()` 後の書き込み・reopen を禁止。

### 8.4 dmnt の扱い
- `nxusDmntPeekMetadata()` = **開かない照会**（`HasCheatProcess` のみ）。読み取り専用コマンド（status）はこちらを使う。
- `nxusDmntGetMetadata()` などは `dmntRunCommand` 経由で repair（ForceOpen）し得る。
- 実機の dmnt は「勝手に開かない」のが正しい。開くのは scan など明示操作。

---

## 9. 開発フロー（このプロジェクトの回し方）

ユーザーの指示は「**サブエージェントを駆使し レビュー → 修正 → レビュー を繰り返す**」。実績のある回し方:

1. **レビュー役を 1 体**（読み取り専用・レポートのみ）＋**修正役を 2〜3 体**を並列に出す。
2. 修正役には**編集してよいファイルを明示**（例: 「`switch/source/nxus_session.c` のみ」）。**ファイルスコープを重複させない**。
3. 修正役のプロンプトに必ず入れる禁止事項:
   - **Switch ビルドはしない**（`aarch64-none-elf-gcc -fsyntax-only` まで）。ビルドは Lead が 1 回だけ実行（並列ビルドは `make` の取り合いになる）。
   - 既存の互換ルール（構造体は末尾追加・長さで判定）を守る。
   - テストを追加したら README の数値も更新対象として報告する。
4. レビュー役の出力は `.reviewNN.md`（gitignored）。**読んだら削除**し、コミットしない。
5. Lead の仕事: エージェントの報告を鵜呑みにせず、**該当箇所を自分で read してから**パッチを当てる。文字列アンカーはインデント差で失敗しやすいので、`grep`/`read` で実物を確認 → 一意なアンカーで置換。
6. 1 ラウンドの完了条件（毎回同じ）:
   ```
   make -C switch clean && bash tools/build.sh   # 警告0 / FAIL 0
   bash tests/run_tests.sh                        # 1,937 checks
   cargo test --release (pc)                       # 124
   python -m unittest discover -s tests (pc)       # 122 ← exe を先にビルド
   python release_packages\_make_packages.py       # パッケージ整合
   git add -A && git commit && git push
   # commit 後に dist を再ビルド（source_rev を HEAD に一致させる）
   git tag -f -a v0.1.0-alpha -m "Nxus-ox Alpha v0.1.0" && git push -f origin v0.1.0-alpha
   gh release upload v0.1.0-alpha <zips + dist/pc/nxus.exe> --clobber
   FTP で実機へ転送（コンソールが起動していれば）
   ```
7. 報告は**簡潔に**: 直したもの（重大度順）→ 検証数値の表 → 次ラウンド候補 → **要再起動**。

### エージェント運用のコツ（実測）
- 同時 3〜4 体まで。それ以上は競合と取りこぼしが増える。
- 「レビュー中に別プロセスがツリーを触る」問題が起きるので、レビュー役には**読むだけ**を徹底させ、`.reviewNN.md` は退避コピーを取らせる。
- 修正役の報告には「触っていないファイル」を明記させる（並列編集の切り分け）。
- 同じファイルを 2 体に触らせた場合は、**必ず Lead が `git diff` で全体を確認**してからビルド。

---

## 10. リリース手順

```powershell
cd C:\anyWorkspace\nx\Nxus
python release_packages\_make_packages.py        # README/metadata 検証 + zip 生成 + boot2 整合
git tag -f -a v0.1.0-alpha -m "Nxus-ox Alpha v0.1.0"
git push -f origin v0.1.0-alpha
gh release upload v0.1.0-alpha `
  "release_packages/Nxus-ox-v0.1.0-alpha-atmosphere.zip" `
  "release_packages/Nxus-ox-v0.1.0-alpha-probe-atmosphere.zip" `
  "release_packages/Nxus-ox-v0.1.0-alpha-windows-x64.zip" `
  "dist/pc/nxus.exe" --clobber
```

- **順序が重要**: 「commit → それから dist を再ビルド → package → upload」。commit 前にビルドすると `metadata.json.source_rev` が 1 つ前のコミットになり、`dirty: true` になる。
- `dist/` と `release_packages/*.zip` は gitignored。`switch/pack/`・`probe/pack/` も gitignored（ビルド生成物が追跡されていた時期があり、そのせいで毎回 dirty になっていた）。
- リリースノート: `release_packages/release-notes-v0.1.0-alpha.md`。

---

## 11. 既知の残課題（優先度順）

1. **テスト空白（最重要）**: `tests/test_server_logic.c` がサーバ側のアルゴリズム（4 KB ページキャッシュのクランプ/ゼロ埋め、frozen 128 件と 32 件イベント上限、tick の scan 進捗と 120 秒 stall の両評価、結果コード 2 系統）を回帰検出する。残る空白は `nxus_debug.c` / `shared/*` と、実スレッドを使う exit drain / detach claim の結合テスト。
2. **`mappingsSample()` が live な struct を返す**: 呼び出し側の `entries`/`count` キャプチャが in-place 再公開を跨ぎ得る（本番は BUSY ゲートで回避、ヘッダに明記済み）。完全に閉じるにはコピー返却への API 変更。
3. **watchdog（修正済み）**: `g_CommandStartedMs` は atomic 化され、scan Running 中も tick は scan 進捗チェックと 120 秒の同期コマンド stall 判定の両方を評価する（無条件 early return は削除）。`tests/test_server_logic.c` がこの契約を固定している。
4. **`system_resource_size = 0x0`**: `.bss` 8.41 MiB + stack `0x8000` = **8.44 MiB の常駐要求**に対して NPDM 側のリソース宣言が 0。現状 WARN のみ（WARN 条件は `.bss + stack > 8 MiB` かつ `system_resource_size == 0`）。実機で OOM を踏んだら最優先で直す。
5. **probe 側のライフサイクル点検**: レポート追記・ローテーション・`probe_started.txt` の扱いは nxus ほど固まっていない。
6. **PC のヒット paging が DROPPED ページでオフセットずれ**（レビュー Low・実機未確認）。
7. **README の記述**: `.bss`/stack、ヒット上限、IPC 削減率、dmnt 修復範囲、ptrscan の 90 秒/150 秒、probe のフォールバックは本ラウンドで実測・実装に合わせた。機能追加時は README の数値と挙動を `grep` で再突き合わせる。
8. **ドキュメント生成の自動化なし**: 手書きは `README.md` のみ。`README.txt` / `DO_NOT_BOOT_TOGETHER.txt` / `metadata.json` は `tools/build.sh` が生成する。文言変更時は `tools/verify_artifact.py` と `_make_packages.py` の両方を通す。

---

## 12. 過去に踏んだ罠（Gotchas）— 同じ失敗をしないために

### プロトコル/結果コード
- **libnx の `MAKERESULT(module, desc)` は bit31 を立てない**: `(module & 0x1FF) | ((desc & 0x1FFF) << 9)`。`Module_Libnx = 345`。したがって `0x00001759` = `(345)|(11<<9)` = **LibnxError_BadInput**。自前コードは `0x80000000 | (484<<9) | desc` だが、**484 は HOS の description フィールド（bit 9-17）で、desc が module フィールド（bit 0-8）** に入る。libnx の `R_MODULE()`/`R_DESCRIPTION()` で自前コードを読むと 484 と desc が入れ替わるため、判別は bit31 + bit 位置で行う。**PC 側で 2 系統を判別してデコードする**（`client.rs::result_text`）。
- `R_FAILED(res)` は libnx では **`(res) != 0`**（bit31 判定ではない）。曖昧なコードは bit31 を明示的に見る。

### スキャン
- `scan refine <値>` の既定比較が **Increased** だったため、値を渡しても全件落ちていた（PC 側 `build_spec`）。今は「値あり → Equal / 値なし → Increased」。`--load`（PC 側リスト）は「値あり → Equal / 値なし → Unchanged」。
- マッピング generation を**毎回**上げると refine が誤って BAD_STATE になる → **内容フィンガープリントで gate**。
- ヒット配列の stride を 8 B のままにすると 8 MiB ヒープを溢れさせる（16 B 化に合わせて上限計算も直す）。
- 窓読みが写像終端を越えると**窓全体が失敗**し、エンジンが dead-end として記憶 → そのヒープ領域のポインタを永久に見つけられなくなる。**クランプ＋ゼロ埋め**が必要。

### ptrscan
- 初期は 20,000 reads で 2 秒打ち切り（MHXX で chains=0）→ **`max_reads = 0`（時計のみ）** に。
- 32 KB の `PtrScan` を 32 KB スタックのワーカーに置くと溢れる → `static` に。
- dmnt の out-count をクランプしないと壊れる。

### debug
- `svcContinueDebugEvent` はイベントが溜まっていると `0xF401` を返す（正常系）。drain を忘れると detach が固まる。
- `g_Debug` を閉じる際は**先に INVALID_HANDLE を公開**してから close（走査スレッドの UAF 回避）。
- `SetRegs` は**アーキ判断を ctx 書き換え前**に行う（32/64 混在で SP/LR/FP が壊れる）。
- `g_Is64Bit` は三状態（unknown/32/64）。attach 時に CreateProcess イベントを drain して確定させる。

### 凍結/終了
- 凍結解除イベントの配列は**最大 32 件・count は総数**。解除ループまで 32 件で打ち切ると**残りが凍結されたまま**になる（実機で 40 件中 8 件が残った）。
- クライアント不在 30 秒で自動解除。イベントは次回接続時にまとめて配信。
- exit は「ゲート → worker join → in-flight drain → 解放」。drain を飛ばすと UAF、待ちすぎるとハング。**諦める場合は解放しない**のが正しい。

### ビルド/配布
- 構造体サイズを変えたら `NXUS_STATIC_ASSERT` と Rust/Python のパリティテストが落ちる。**フレーム長で新旧判定**する設計を維持。
- `switch/pack/main` などの生成物をコミットしない（`.gitignore` 済み）。
- ホスト C テストのスタブに関数を足し忘れるとリンクエラー（`nxusDmntTargetIncarnation` で実際に踏んだ）。
- Rust のテストは**モジュール直下**に置く。`#[test]` を関数内に入れると「テストされない fn」になり、件数が増えないのに気づきにくい。

### 実機
- sysmodule は起動時のみロード。**exefs.nsp 更新＝再起動必須**。
- probe と nxus の同時 boot 禁止。
- FTP は 1 回タイムアウトすることがある（疎通確認 → 再試行）。
- `status` が `pid 0` でも異常とは限らない（dmnt 未オープン）。`metadata` は dmnt を開くので値が返る。

---

## 13. トラブルシューティング

| 症状 | 原因の候補 | 対処 |
|---|---|---|
| `metadata` が `0x0032C80D` | dmnt の cheat process 未オープン | `scan begin` 等を実行。`status` では開かない |
| `scan refine` が 0 件 | 旧 PC クライアントの既定比較バグ / 既に 0 件 | 最新 exe。空リストは `0x8003C806` が正常 |
| `scan refine` が BAD_STATE | ターゲット変更・incarnation 変更・写像再構築で解決不能 | 再スキャン。ログに `revalidated`/`resolved - dropped` が出る |
| `ptrscan` が chains=0 で即終了 | 旧ビルド（read budget 20k） | 新ビルド。ログに `max_reads=0 (unlimited...)` |
| `frozen list` が残っている | 自動解除前（30 秒未満） | 30 秒待つ。ログ `frozen: releasing N address(es)` |
| ホストテストがリンクエラー | `tests/stubs` に新シンボルがない | スタブ追加 |
| Python E2E が freshness で落ちる | `nxus.exe` が古い | `cargo build --release` |
| `verify_artifact.py` が FAIL | README/metadata/title-id 不整合、NPDM フラグ | 出力の FAIL 行を読む。boot2 は `NXUS_STAGE_PROBE` で再導出 |
| 実機が接続できない | 本体スリープ / sysmodule 未起動 / IP 変更 | 本体を起こす、`Test-NetConnection`、`status` |

---

## 14. 用語

- **dmnt**: Atmosphère のデバッグモニタ。`dmnt:cht` 経由でメモリ読み書き・凍結・メタデータ取得。
- **incarnation**: dmnt が掴んでいる「プロセスの世代」。再起動で +1。
- **mapping generation**: Nxus が公開する写像表の世代（内容が変わった時だけ +1）。
- **pin / retire**: 写像ブロックの参照カウント方式。旧ブロックは retire 後に解放。
- **claim**: 「この処理は 1 本だけ」を保証する CAS ベースの排他（scan / ptrscan / debug teardown）。
- **terminal gate**: 終了後に新規コマンドを拒否する仕組み（`g_ServerExited`）。
- **hit revalidation**: 写像再構築時に絶対アドレスでヒットを引き直す処理。
- **SoA**: ヒットの値配列（`values`）とメタ配列（`addresses`）を分けて持つレイアウト。

---

## 15. 参照ドキュメント

| ファイル | 内容 |
|---|---|
| `README.md` | 利用者向け本体（機能・導入・CLI・検証数値） |
| `docs/PC_CLIENT.md` | PC クライアント詳細（GUI/CLI/式評価） |
| `docs/DESIGN.md` | 設計とプロトコル |
| `docs/DEBUG_MODE.md` | デバッガの使い方 |
| `docs/HOTKEY.md` | ホットキー / auto-continue |
| `docs/BRIEF_WATCHPOINTS.md` | ハードウェアウォッチポイント解説 |
| `docs/CHEAT_CODE_SEMANTICS.md` | チートコード生成の意味論 |
| `docs/NPDM_DEBUG_FLAGS.md` | NPDM/ACID デバッグビット |
| `docs/MHXX_3DS_TO_SWITCH_PORTING.md` | MHXX 移植・実機検証メモ |
| `docs/NEXT_TASKS.md` | 残タスク（本書 11 章と重複可） |
| `docs/HARDWARE_DAY1.md` | 実機初日メモ |
| `docs/REVIEW_LOG.md` | ラウンドごとのレビュー履歴（判断の経緯） |

---

## 16. 最初にやるべきこと（引継ぎ直後のチェックリスト）

1. `git log -n 3 --oneline` / `git status` が clean か確認。
2. `bash tools/build.sh` が警告 0・FAIL 0 で通るか。
3. 3 スイート（ホスト C / Rust / Python）を回して数値が README と一致するか。
4. 実機が起動していれば `status` / `log` で**動いているビルド**を確認（`build <date>`）。
5. `docs/REVIEW_LOG.md` と本 11 章を読み、次にやる 1 件を決める（推奨は **11 章の 1 の残り: nxus_debug / shared のテスト**）。
6. 1 ラウンド分の修正 → 検証 → commit → リリース → 実機転送 → 報告（**要再起動**）。

---

### 連絡・判断に迷ったら
- 「実機でしか再現しない」問題は、PC 側の CLI 出力と `nxus log` を必ずセットで取る（今回の refine バグはこの方法で特定した）。
- 安全性に関わる変更（所有権・解放・終了）は、**「安全側に倒す」**（リークは許容、UAF は不可）を原則にする。
- 迷ったらユーザーに「A: 安全性優先（解放しない）/ B: 復旧性優先（再初期化する）」の二択で聞く。過去の判断はすべてこの基準で記録されている。
