# 同梱フォント

- `MPLUS1p-Regular.ttf` … **M PLUS 1p Regular**（日本語対応、OFL）
  - 取得元: https://github.com/google/fonts/tree/main/ofl/mplus1p
  - ライセンス: `MPLUS1p-OFL.txt`（SIL Open Font License 1.1）
  - 目的: Windows のエラーメッセージやゲーム内文字列など**日本語**を表示するため。
    egui 既定フォントはラテン文字のみで、日本語は □（豆腐）になっていた。
- 使い方: `src/gui/mod.rs` の `font_definitions()` が Proportional / Monospace の
  **フォールバック**として追加する（ラテン文字は既定フォントのまま）。
- 被覆は `gui::font_tests::bundled_font_covers_japanese` が実際に検証している。
- 差し替える場合: 同じフォルダに置いて `JP_FONT` のパスを変え、テストの文字列が通ることを確認する。