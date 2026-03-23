#!/usr/bin/env bash
set -euo pipefail

if rg -n "^(<<<<<<<|=======|>>>>>>> )" . >/tmp/conflict_hits.txt; then
  echo "❌ 检测到 merge conflict 标记："
  cat /tmp/conflict_hits.txt
  exit 1
fi

echo "✅ 未检测到 merge conflict 标记"
