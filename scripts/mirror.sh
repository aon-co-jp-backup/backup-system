#!/usr/bin/env bash
# aon-co-jp の公開リポジトリを、検査・匿名化したうえで aon-co-jp-backup へ同名ミラーする。
# 必要な環境変数: BACKUP_PAT(aon-co-jp-backupのPAT)、GH_TOKEN(読み取り用、Actions標準で可)
# 任意: SRC_OWNER(既定 aon-co-jp)、DST_OWNER(既定 aon-co-jp-backup)、ONLY(指定時はそのリポジトリだけ)
set -uo pipefail
SRC_OWNER="${SRC_OWNER:-aon-co-jp}"
DST_OWNER="${DST_OWNER:-aon-co-jp-backup}"
ONLY="${ONLY:-}"
MAX_NEW="${MAX_NEW:-5}"
CREATED_COUNT=0
CREATE_BLOCKED=0
WORK="$(mktemp -d)"
SCRIPTS="$(pwd)/scripts"
CONF="$(pwd)/.gitleaks.toml"
STATUS="$(pwd)/status.tsv"
: > "$STATUS"

# 公開かつアーカイブされていないリポジトリ。非公開は構造上ここに現れない。
if [ -n "$ONLY" ]; then
  repos="$ONLY"
else
  repos="$(gh api "users/$SRC_OWNER/repos?per_page=100" --paginate -q '.[]|select(.visibility=="public")|.name')"
fi

# 危険なファイル名(履歴に1度でも存在したら停止)
DANGER='(^|/)(\.env|\.env\.[a-z]+|id_rsa[^/]*|id_ed25519[^/]*|[^/]*\.(pem|key|p12|pfx|sqlite3?|db|dump|sql\.gz|kdbx))$'
SAFE_DANGER='(^|/)(testdata|fixtures?)/|\.env\.example$'

record() { printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$STATUS"; echo "[$2] $1 $3"; }

for name in $repos; do
  d="$WORK/$name.git"
  if ! git clone --quiet --mirror "https://x-access-token:${GH_TOKEN}@github.com/$SRC_OWNER/$name.git" "$d" 2>/dev/null; then
    record "$name" "error" "clone失敗"; continue
  fi
  cd "$d"

  # 1) 秘密情報(全履歴)
  if ! gitleaks git --config "$CONF" --redact --no-banner --report-format json --report-path "$WORK/$name.leaks.json" "$d" >/dev/null 2>"$WORK/$name.leaks.err"; then
    n="$(grep -c '"RuleID"' "$WORK/$name.leaks.json" 2>/dev/null || echo '?')"
    [ -s "$WORK/$name.leaks.err" ] && head -c 400 "$WORK/$name.leaks.err" | tr "
" " " | sed "s/^/  gitleaks stderr: /"; echo
    record "$name" "blocked" "gitleaks検出 ${n}件(要確認・失効)"
    jq -r '.[]|"  検出: \(.RuleID) \(.File):\(.StartLine) commit=\(.Commit[0:8])"' "$WORK/$name.leaks.json" 2>/dev/null | sort | uniq -c | head -20
    cd - >/dev/null; continue
  fi

  # 2) 危険なファイル名
  bad="$(git log --all --name-only --format= | sort -u | grep -E -i "$DANGER" | grep -v -E -i "$SAFE_DANGER" | head -5 | tr '\n' ' ')"
  if [ -n "$bad" ]; then
    record "$name" "blocked" "危険なファイル名: $bad"; cd - >/dev/null; continue
  fi

  # 2b) 個人情報(HEADのテキストを走査)。検出したら止め、該当ファイルを非公開アーカイブへ退避する。
  if ! python3 "$SCRIPTS/pii_scan.py" "$d" "$WORK/$name.pii.json"; then
    bash "$SCRIPTS/quarantine.sh" "$name" "$d" "$WORK/$name.pii.json" || true
    record "$name" "blocked" "個人情報の疑い(詳細は退避先のレポート。元は要確認)"; cd - >/dev/null; continue
  fi

  # 3) コミットのメールを匿名化(noreply以外は置換)。元の履歴は変えない。
  git filter-repo --force --quiet --email-callback '
import re
e = email.decode("utf-8", "replace")
return email if re.search(r"noreply", e) else b"anonymous@users.noreply.github.com"
' || { record "$name" "error" "filter-repo失敗"; cd - >/dev/null; continue; }

  # 4) 宛先を用意(無ければ作成。Actionsは無効化して、ミラー先でワークフローが勝手に動かないようにする)
  if ! GH_TOKEN="$BACKUP_PAT" gh api "repos/$DST_OWNER/$name" >/dev/null 2>&1; then
    # 新規作成は二次レート制限が厳しいので、1回の実行あたりの件数を絞り、間隔を空ける。
    # 上限に当たったら、この回は以降の新規作成を打ち切る(次回以降の実行で追いつく)。
    if [ "$CREATE_BLOCKED" = 1 ] || [ "$CREATED_COUNT" -ge "$MAX_NEW" ]; then
      record "$name" "pending" "新規作成待ち(作成上限のため次回以降)"; cd - >/dev/null; continue
    fi
    if ! GH_TOKEN="$BACKUP_PAT" gh repo create "$DST_OWNER/$name" --public          --description "Auto mirror of $SRC_OWNER/$name (sanitized; do not edit)" >/dev/null 2>"$WORK/$name.create.err"; then
      CREATE_BLOCKED=1
      record "$name" "pending" "作成上限に到達: $(tr '
' ' ' < "$WORK/$name.create.err" | cut -c1-80)"; cd - >/dev/null; continue
    fi
    CREATED_COUNT=$((CREATED_COUNT+1))
    GH_TOKEN="$BACKUP_PAT" gh api -X PUT "repos/$DST_OWNER/$name/actions/permissions" -F enabled=false >/dev/null 2>&1 || true
    sleep 90
  fi

  # 5) ブランチとタグだけ push(refs/pull/* などは送らない)
  if git push --quiet --prune --force "https://x-access-token:${BACKUP_PAT}@github.com/$DST_OWNER/$name.git" \
        '+refs/heads/*:refs/heads/*' '+refs/tags/*:refs/tags/*' 2>"$WORK/$name.push.err"; then
    record "$name" "ok" "同期完了"
  else
    record "$name" "error" "push失敗: $(tr '\n' ' ' < "$WORK/$name.push.err" | cut -c1-120)"
  fi
  cd - >/dev/null
  rm -rf "$d"
done

# 6) 非公開化・削除されたのに公開ミラーが残っているもの(要手動確認)
if [ -z "$ONLY" ]; then
  GH_TOKEN="$BACKUP_PAT" gh api "users/$DST_OWNER/repos?per_page=100" --paginate -q '.[].name' | while read -r m; do
    [ "$m" = "backup-system" ] && continue
    echo "$repos" | grep -qx "$m" || record "$m" "orphan" "元が公開でない/存在しない。ミラーを手動確認"
  done
fi
