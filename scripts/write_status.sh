#!/usr/bin/env bash
{
  echo "# 同期状況"; echo
  echo "最終実行: $(date -u '+%Y-%m-%d %H:%M UTC')"; echo
  echo "| リポジトリ | 状態 | 詳細 |"; echo "|---|---|---|"
  sort status.tsv | awk -F'\t' '{printf "| %s | %s | %s |\n",$1,$2,$3}'
} > STATUS.md
