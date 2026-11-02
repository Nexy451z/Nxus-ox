# エージェント運用プレイブック（司令塔のためのプロンプト設計）

最終更新: 2026-11-02
対象: `C:\anyWorkspace\nx\Nxus`（Nxus-ox）／ MHXX 解析など関連ワークスペース
由来: 前任司令塔（DeepSeek v4.1 flash / 別ハーネス）の実プロンプトを分析して抽出した型

---

## 0. この文書の使い方

1. 章 1 の「型」を読む（なぜ効くのか）。
2. 章 2 のテンプレートをコピーして、対象・アドレス・制約を埋める。
3. 章 3 の分担パターンでワーカーを並べる。
4. 章 4 のアンチパターンに陥っていないか確認。
5. 章 5 のチェックリストで送信前チェック。

ツール対応（このハーネス）:

| やりたいこと | 使うもの |
|---|---|
| 1 体だけ独立タスク | `subagent`（履歴なし） |
| 文脈を引き継いだ派生タスク | `subagent_fork` |
| 名前付きで会話・再利用するチーム | `spawn_teammate`（+ `send_message` / `wait_agent` / `list_agents`） |
| 10 本以上の fan-out / パイプライン | `workflow`（JS スクリプトで一括） |
| 共有タスクボード | `team_task_create` など |
| 進捗の可視化 | `todo_write` |

> 別ハーネス用の `run.js`（MCP）は**このハーネスでは不要**。同じプロンプトを `subagent` の `prompt` に渡せばよい。

---

## 1. 前任司令塔のプロンプトの型（分析）

実例から抽出した 8 つのブロック。**上から順に書く**と迷いがない。

### ① ヘッダ：対象の同一性と環境

```
Investigate MHXX Switch (0100C3800049C000, build_id 9D4C86E6EF74504A, AArch32)
stamina check / dodge check / dash exhaustion mechanics using Ghidra
(C:/anyWorkspace/nx/mhxx/ghidra/MHXX.rep) and
C:/anyWorkspace/nx/mhxx/extract/upd/image/main.bin
(remember: Ghidra address = file offset + 0x100!)
```

- タイトル名・タイトルID・**build_id**・アーキテクチャを 1 行で。
- **道具の絶対パス**を書く（ワーカーは cwd を推測しない）。
- **変換規則・不変条件**を丸括弧で明示（`Ghidra addr = file offset + 0x100`）。
  ここを書き忘れると、返ってきたアドレスが全部 0x100 ずれる。

### ② ゴール：ユーザーが欲しい振る舞い（非ゴール込み）

```
Goal:
Instead of freezing stamina or preventing stamina consumption, the user wants a
cheat where stamina checks are bypassed so the hunter can STILL dodge and keep
dashing even when current stamina is 0, without triggering the panting animation,
while allowing stamina to decrease/recover normally.
```

- 「何をするか」だけでなく **「何をしないか」** を書く。前任者は `Instead of ...` で
  既に却下したアプローチを明示し、ワーカーが同じ袋小路に入るのを防いでいる。
- 体感（ユーザー視点）で書く。実装手段は書かない（手段はワーカーの仕事）。

### ③ コンテキスト：既知のこと（再発見させない）

```
Context from existing Stamina Infinite cheat (P8):
The 6 sites in P8 are:
- file offset 0x002A0E24 (Ghidra 0x002A0F24)
  ...
And near 0x002A0E34 it calls file offset 0x00278B5C.
```

- 既に分かっているアドレス・構造・ポインタ式（`[[main+0x2148F48]+0x58]`）を全部書く。
- **両方の座標系**（file offset と Ghidra アドレス）を併記する。
- ここをケチると、ワーカーが同じ探索をやり直して時間と枠を浪費する。

### ④ ワーカーのロール名（専門性の明示）

```
Tasks for Worker S1 (Ghidra Decompiler & Stamina Field Xref Analyzer):
Tasks for Worker S2 (Live Switch & Binary Disassembly Xref Analyzer):
Tasks for Worker M1 (mhxx_port & Archive Monster Struct / Damage Function Researcher):
Tasks for Worker M2 (monster HP update function, live enemy RAM, and code-cave design):
```

- 名前を付けることで、**成果物の粒度と手法が固定**される。
- 同じロールを 2 体出さない（重複＝枠の無駄）。ロールは「手法」で切る：
  - 静的解析（Ghidra / 逆コンパイル）
  - 動的解析（実機・生メモリ）
  - アーカイブ検索（既存資料・リポジトリ）
  - 設計（パッチ設計・コードケーブ・検証）

### ⑤ 番号付きタスク（それぞれが検証可能な成果物）

```
1. Decompile and inspect the functions containing those 6 sites (...), plus 0x278B5C
   and the virtual method at vtable +0x210 ([r0, #0x210]).
2. Identify the exact player struct offset for current stamina (f32) and max stamina
   (f32), and find ALL functions that: a) check current stamina > 0 before dodge,
   b) check <= 0 during dash to trigger exhaustion, c) subtract stamina and whether
   it sets an 'exhausted' flag.
3. Report exact file offsets (main+offset), original ARM32 instructions, decompiled
   logic, and the cleanest patch candidates so that stamina can decrease to 0 but
   dodge/dash are always allowed and exhaustion never triggers.
```

- 1 項目 = 1 アクション + 1 成果物。形容詞ではなく**動詞**で終える。
- 「ALL functions that ...」のように**網羅条件**を明示する。
- 最後に**出力フォーマット**を指定する（章 ⑧）。

### ⑥ 制約・手法の指定

```
Using C:/apps/nxus/nxus.exe in READ-ONLY mode (`status`, `metadata`, `read`, `disasm`)
against the live Switch at 192.168.1.13, and Python with .../main.bin:
```

- 触ってよい道具・モード・接続先・ファイルを列挙。
- **書き込み禁止**なら `READ-ONLY` と明記（暴走防止）。
- 解析対象のアドレス範囲を書く（`main + 0x0029AB00..0x0029BD00` など）。

### ⑦ 仮説の種（"Think about this"）

```
2. ... is there dead/unused code space ... ?
   - YES! Think about this: if we disable normal stamina changes by putting
     `bx lr` at the entry of 0x002A0DB0, the ENTIRE body of 0x002A0DB4..0x002A0F0C
     (85 instructions = 340 bytes) becomes never-executed dead code that can be
     used as an in-module code cave ...
3. Verify if 0x002A0DB0..0x002A0F0C has any internal branch targets from outside ...
```

- 開かれた問いだけ投げると、ワーカーは無難な要約を返してくる。
- **具体的な仮説＋その検証方法**を渡すと、当たり外れに関わらず情報が出る。
- 「YES! Think about this:」のような**熱量**も有効（モデルは強く誘導される）。

### ⑦' 仮説には必ず「反証条件」を添える（追記）

仮説の種は強力だが、**誘導が強すぎるとワーカーが「合わせにいく」**（確証バイアス）。
前任者の例は熱量があって刺さる反面、`YES! Think about this:` だけだと
「本当に安全か」の検証が薄くなり得る。次の 2 行を足すとバランスが取れる:

```
Assume the hypothesis may be WRONG. Before agreeing, list the evidence that would
falsify it, and check at least one of those items concretely. If a simpler or safer
alternative exists, propose it explicitly.
```

- 期待する出力: `hypothesis: supported / refuted / undecided` ＋ 反証のために見た事実。
- 「undecided」を許すと、無理に断定しなくなる（＝嘘の確度が減る）。

### ⑧ 成果物の契約（出力フォーマット）

```
Report all findings, exact offsets, original/patched instruction words, live struct
verification, and the exact ARM32 assembly routine.
```

- 何をどの形式で返すかを列挙。曖昧だと散文が返る。
- コード変更を伴うタスクなら「編集してよいファイル」を明記（下記テンプレ参照）。

---

## 2. コピペ用テンプレート

### T1. 静的解析ワーカー（逆コンパイル / xref）

```
【対象】<タイトル名> (<TITLE_ID>, build_id <BUILDID>, <ARCH>) の <機能>
【道具】<逆コンパイル環境> と <バイナリの絶対パス>
（不変条件: <アドレス変換規則>）

【ゴール】
<ユーザーが欲しい振る舞い。しばしば "Instead of X, we want Y without Z" の形>

【既知のコンテキスト】
- <既存チート/既存解析のサイト一覧・アドレス・ポインタ式>
- <既に試して駄目だった方法>

【あなたのロール】Worker <ID> (<手法を表す名前>)
【タスク】
1. <対象関数の特定と逆コンパイル>（<アドレス範囲>）
2. <フィールド/呼び出し元の網羅>（"find ALL functions that ..."）
3. <設計に必要な情報の抽出>
4. <成果物の形式で報告>

【制約】
- <読み取り専用 / 触ってよいファイル>
- <解析してよいアドレス範囲>

【報告フォーマット】
- アドレスは <file offset (main+0x...)> と <逆コンパイラ側アドレス> を併記
- 元の命令 / 候補パッチの命令語を 16 進で
- 確度（高/中/低）と根拠
```

### T2. 実機・動的解析ワーカー

```
【対象】実機 <IP> の <タイトル>（<TITLE_ID>, build_id <BUILDID>）
【道具】<クライアントの絶対パス> を **READ-ONLY**（status / metadata / read / disasm のみ）
　　　　<ローカルのバイナリ> と併用

【ゴール】<実機で観測したいこと>

【タスク】
1. `status` / `metadata` でターゲットを確認し、<確認したいポインタ式> を読む
2. <アドレス範囲> を disasm し、<静的解析の結果> と突き合わせる
3. <ライブの値> と <ファイル上の値> の差分を報告
4. 失敗した場合は、その時点の生メモリと読み取り結果を必ず添えて報告

【制約】書き込み禁止（freeze / write は使わない）。<スキャンは使わない 等>
【報告フォーマット】アドレス・生バイト・解釈・確度
```

### T3. リポジトリ / 資料検索ワーカー

```
【対象】<リポジトリ or 資料ディレクトリの絶対パス>（複数可）
【ゴール】<探している構造体・関数・仕様>

【タスク】
1. <名前のバリエーション> でコードとドキュメントを横断検索
2. 見つけた定義を <ファイル:行> で列挙し、<型/サイズ/意味> を要約
3. 見つからなかった場合は「無い」と明言し、近い候補を提示
4. <矛盾する記述があれば列挙>

【制約】読み取り専用。ビルド・実行はしない。
```

### T4. 実装（修正）ワーカー

```
【対象ファイル】<編集してよいファイルを列挙。これ以外は触らない>
【禁止】Switch ビルドはしない（構文確認 `-fsyntax-only` まで。ビルドは Lead が 1 回だけ）
【問題】<症状・再現条件・期待動作。可能ならログ/実測値>
【原因の仮説】<あれば。無ければ「未特定」と明記>
【タスク】
1. <該当箇所を読み、原因を特定>（推測で書かない。行番号 or 関数名を報告）
2. <修正を実装>
3. <テストを追加/更新>（<テストコマンド>）
4. 変更点・副作用・テスト結果を報告

【守るべき制約】
- 互換ルール: <例: 構造体は末尾追加のみ / フレーム長で新旧判定>
- 予算: <例: 8 MiB ヒープ>
- 安全側: <例: UAF は不可、リークは許容>

【報告フォーマット】
- 変更ファイル / 関数 / 行
- 挙動の before/after（1 行ずつ）
- テスト結果（数値）
- 触っていないファイル（並列作業の切り分け用に明記）
```

### T5. レビューワーカー（敵対的検証）

```
【読み取り専用】ソース編集禁止。レポートのみ。
【対象】<HEAD のコミット or 作業ツリー>
【テーマ】<例: 「解放と公開の対応 — 二重 free が残っていないか」>

【重点】
1. <危険なパターン 1>（関数名/ファイルを指定）
2. <危険なパターン 2>
3. <既知の残課題リスト> が HEAD で残っているか
4. <数値の一致（テスト本数・README・dist）>

【出力】`.reviewNN.md` に「重大度 × file:line × 内容 × 修正案 × 確度」最大 12 件。
　　　　日本語。返り値は 10 行以内の要約。
【注意】レビュー中に作業ツリーが動くことがある。対象コミットを明記し、読んだ時点を書く。
```

### T6. 統合（マージ）ワーカー

```
【入力】ワーカー <A>, <B>, <C> の報告（下記に貼る）
【タスク】
1. 矛盾点を列挙（同じアドレスで異なる結論、片方だけが観測した事実）
2. 矛盾は「どちらが正しいか」ではなく「どうすれば決着するか（追加観測）」を書く
3. 次に投げるべきワーカープロンプトを 1 本書く
```

---

## 3. 分担パターン（前任者の実践）

### パターン A: 手法で 4 分割（今回の実例）

| Worker | 手法 | 成果物 |
|---|---|---|
| S1 | 静的逆コンパイル（Ghidra） | フィールドオフセット・関数の意味・候補パッチ |
| S2 | 実機＋バイナリ xref | ライブ struct 検証・呼び出し関係 |
| M1 | アーカイブ検索 | 既存資料の該当箇所 |
| M2 | 設計＋検証 | コードケーブ設計・分岐ターゲット検証 |

→ **同じ問いを 4 つの独立した証拠源から**取る。どれか 1 つが外れても他で埋まる。

### パターン B: レビュー × 修正のループ（Nxus で実績）

1. レビュー役 1 体（読み取り専用）＋ 修正役 2〜3 体（**ファイルスコープを重複させない**）を同時に出す。
2. 修正役の報告を Lead が自分で read して裏取り → パッチ。
3. 全スイート実行 → commit → リリース → 実機。
4. 次のレビュー役を出す（前回の指摘リストが入力になる）。

### パターン C: 大規模 fan-out（10 本以上）

`workflow` で JS を書く。`pipeline(items, stage1, stage2)` は**バリアなし**なので、
「ファイルごとに解析 → 修正案生成」を並列に流せる。全体を待つ必要がある段だけ `parallel`。

### 分担の原則

- **書き込みスコープを重複させない**（同一ファイルを 2 体に触らせない）。
- **読み取りは重複してよい**（複数の証拠源はむしろ歓迎）。
- ワーカー数は **3〜5 体**が実測で一番効率が良い。それ以上は取りこぼしが増える。
- 依存がある場合は `team_task_create` の `blocked_by` で順序を明示。

---

## 4. アンチパターン（これをやると枠を溶かす）

| アンチパターン | 何が起きるか | 代わりに |
|---|---|---|
| 「X を調べて」だけ | 一般論の要約が返る | ①〜⑧ を埋める |
| パスを書かず cwd 推測に任せる | 別ディレクトリを掘る | 絶対パスを明記 |
| 変換規則を書かない | アドレスが 0x100 ずれる | 不変条件を括弧書き |
| 非ゴールを書かない | 却下済みの案を再提案 | `Instead of X, we want Y` |
| 出力形式を書かない | 散文が返り、Lead が解釈で消耗 | フォーマットを列挙 |
| 2 体に同じファイルを触らせる | 競合・上書き・意味不明な diff | スコープを分ける |
| ワーカーにビルドさせる | 並列ビルドで壊れる | Lead が 1 回だけ |
| 仮説なしの open question | 無難な結論 | 「Think about this: ...」で種を渡す |
| 仮説を断定で押し付ける | ワーカーが合わせにいき、反証を探さない | 仮説＋**反証条件**＋代替案の要求 |
| 報告を鵜呑みにする | 存在しない行番号でパッチが失敗 | Lead が必ず read で裏取り |

---

## 5. 送信前チェックリスト

- [ ] ① 対象（タイトルID / build_id / arch）と**道具の絶対パス**、変換規則を書いた
- [ ] ② ゴールを**ユーザーの振る舞い**で書き、**非ゴール**も書いた
- [ ] ③ 既知のアドレス・ポインタ式・却下済み案を全部書いた
- [ ] ④ ワーカーの**ロール名**を付けた（手法が 1 つに定まる名前）
- [ ] ⑤ タスクは**番号付き**で、各項目が検証可能な成果物になっている
- [ ] ⑥ 触ってよい道具・ファイル・アドレス範囲・モード（READ-ONLY 等）を書いた
- [ ] ⑦ 仮説があれば「Think about this」で種を渡し、**反証条件と代替案の要求**も添えた
- [ ] ⑧ 報告フォーマット（アドレス併記・16 進命令語・確度・触っていないファイル）を指定した
- [ ] 並列に出す場合、**書き込みスコープが重複していない**
- [ ] ビルドやリリースなど**排他が必要な操作**をワーカーに渡していない

---

## 6. 実例（Nxus 文脈に翻案）

前任者の S1 を、このリポジトリの作業にそのまま使う形にした例：

```
Investigate Nxus-ox cheat VM (C:\anyWorkspace\nx\Nxus) — PC-side Atmosphere
cheat engine: pc/Nxus.Cli/src/cheat/{parser,vm,manager}.rs
Target format reference: Atmosphere cheat codes, build id 9D4C86E6EF74504A (MHXX).

Goal:
We want the VM to be byte-exact against Atmosphere's dmnt-cheat interpreter for
the opcode families it claims to support, so a cheat that works in Atmosphere
behaves identically here — including register save/restore masks and the
keypad-conditional branch that reads status.keys_held.

Context from existing work:
- 79 Rust tests already cover parser/VM/manager.
- `NxusStatus.keys_held` was appended at the end (84 B; NXUS_STATUS_MIN_SIZE 76).
- VM rejects unsupported opcodes per block with an error string (by design).

Tasks for Worker V1 (opcode semantics & reference-diff):
1. For each opcode family in cheat/vm.rs, write down the semantics you implement
   (widths, register file, condition codes, mask handling, 0xFF0/0xFF1).
2. Compare against Atmosphere's dmnt_cheat_vm semantics as documented in
   docs/CHEAT_CODE_SEMANTICS.md; list every divergence with file:line.
3. Report which divergences are observable (would change a cheat's result) and
   which are cosmetic.

Constraints: read-only; do not build; do not touch the Switch sources.

Report: table of opcode → implemented behavior → reference behavior → verdict
(identical / divergence-observable / divergence-cosmetic) + confidence.
```

---

## 7. 記録

- このプレイブックは「上手くいった型」を残すためのもの。**新しい型が当たったら追記する**。
- 失敗したプロンプトも 4 章に追記する（同じ轍を踏まないため）。
