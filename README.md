# backup-system

`aon-co-jp` の**公開**リポジトリを、検査・匿名化したうえで `aon-co-jp-backup` へ同名で自動ミラーする。
GitHub Actions(3時間おき+手動)。結果は [STATUS.md](STATUS.md)。

- 非公開リポジトリは対象外(公開一覧のみ取得)。新しい公開リポジトリは自動で対象になる。
- 全履歴を gitleaks で検査し、検出があればそのリポジトリは同期せず `blocked` と記録する。
- `.env`・秘密鍵・DBなどのファイル名が履歴にあれば同様に停止する。
- コミットのメールアドレスは、noreply以外をミラー側だけ匿名化する(元の履歴は変更しない)。
- ミラー先のActionsは無効化する。ブランチとタグのみ送る。

限界: 個人情報(氏名・住所など)は機械で完全には検出できない。blocked一覧と定期的な目視確認を併用すること。
Secrets: `BACKUP_PAT`(必須)。

## 個人情報の検出と退避
- `scripts/pii_scan.py`: HEADのテキストをルール(メール・日本の電話・住所・マイナンバー・カード番号〈Luhn〉)で走査。
  カード/マイナンバー/住所、またはデータ系ファイル(csv/json/sql等)に多数、または大量の検出で**ミラーを止める**。
  READMEの連絡先1件程度は警告のみ。レポートには**値を書かない**(件数と位置のみ)。
- `scripts/quarantine.sh`: 止めたリポジトリの該当ファイルを非公開 `aruaru-db-archive/quarantine/<repo>/` へ複製(Secret `ARCHIVE_PAT` が必要)。
  元リポジトリ側の削除・履歴書き換えは自動では行わない(人が1件ずつ確認)。
- 任意: Secret `ARUARU_LLM_URL`/`ARUARU_LLM_TOKEN` があれば、曖昧(warn)なものを aruaru-llm の `/v1/classify-pii` で二次判定する(このエンドポイントは aruaru-llm 側に未実装)。

## ミラーに含めないもの(再取得できるものはバックアップしない)
ミラー作成時のみ、次を履歴から取り除く(元リポジトリは変更しない): 20MBを超えるファイル、モデル(`*.gguf`/`*.safetensors`/`*.onnx`/`*.ckpt`/`*.pt`/`*.pth`、`models/*`)、`install/*/*.exe`。
モデルは各アプリの自動ダウンロード機能(例: aruaru-llm の `/v1/recommend-and-download`)で復元する前提。
このため、ミラーは「ソースコードの完全なバックアップ」であり、大きなバイナリの完全なバックアップではない。バイナリが必要な場合は元のリポジトリ/Releasesを参照すること。
例外: `install/data/open-english.sqlite3`(空のDB、誤コミットの成果物と確認済み)は危険ファイル名の検査から除外。
