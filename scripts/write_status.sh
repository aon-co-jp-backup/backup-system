#!/usr/bin/env bash
{
  echo "# 同期状況"; echo
  echo "最終実行: $(date -u '+%Y-%m-%d %H:%M UTC')"; echo
  echo "| リポジトリ | 状態 | 詳細 |"; echo "|---|---|---|"
  cat status.tsv status.tsv.warn 2>/dev/null | sort | awk -F'\t' '{printf "| %s | %s | %s |\n",$1,$2,$3}'
} > STATUS.md
