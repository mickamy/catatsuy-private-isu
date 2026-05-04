#!/bin/bash
set -euo pipefail

DB_USER=isuconp
DB_PASS=isuconp
DB_NAME=isuconp
DB_HOST=127.0.0.1
DB_PORT=3307

DEST=/home/isucon/private_isu/webapp/public/image
mkdir -p "$DEST"

export MYSQL_PWD="$DB_PASS"

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

# 1クエリで全件 (id, mime, base64) を取得
mysql -h"$DB_HOST" -P"$DB_PORT" -u"$DB_USER" "$DB_NAME" \
  --batch --skip-column-names --raw \
  -e "SELECT id, mime, TO_BASE64(imgdata) FROM posts" > "$TMP"

count=0
skipped=0
while IFS=$'\t' read -r id mime b64; do
  case "$mime" in
    image/jpeg) ext=jpg ;;
    image/png)  ext=png ;;
    image/gif)  ext=gif ;;
    *) continue ;;
  esac
  out="$DEST/${id}.${ext}"
  if [[ -f "$out" ]]; then
    skipped=$((skipped+1))
    continue
  fi
  printf '%s' "$b64" | base64 -d > "$out"
  count=$((count+1))
done < "$TMP"

echo "done: written=$count skipped=$skipped dest=$DEST"
ls "$DEST" | wc -l
