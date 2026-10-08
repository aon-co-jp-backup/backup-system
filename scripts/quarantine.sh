#!/usr/bin/env bash
# PII検出ファイルを非公開の aruaru-db-archive/quarantine/<repo>/ へ退避(複製)する。
# 引数: <repo名> <git-dir> <pii-report.json>。ARCHIVE_PAT が無ければ何もしない。
# 元リポジトリ(aon-co-jp)側の削除・履歴書き換えは行わない(人が1件ずつ確認する)。
set -uo pipefail
name="$1"; d="$2"; rep="$3"
[ -n "${ARCHIVE_PAT:-}" ] || { echo "  quarantine: ARCHIVE_PATなし、スキップ"; exit 0; }
A="$(mktemp -d)"
git clone -q "https://x-access-token:${ARCHIVE_PAT}@github.com/${ARCHIVE_REPO:-aon-co-jp/aruaru-db-archive}.git" "$A" || { echo "  quarantine: archive clone失敗"; exit 1; }
dst="$A/quarantine/$name"; mkdir -p "$dst"
jq -r '.findings[]|select(.level=="block")|.path' "$rep" | while read -r p; do
  mkdir -p "$dst/$(dirname "$p")"
  git -C "$d" cat-file blob "HEAD:$p" > "$dst/$p"
done
cp "$rep" "$dst/_pii-report.json"
cd "$A"; git add -A
git diff --cached --quiet || { git -c user.name=backup-bot -c user.email=backup-bot@users.noreply.github.com commit -qm "quarantine: $name(PII検出、元リポジトリは要確認)" && git push -q; }
