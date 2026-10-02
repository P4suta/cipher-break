#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -uo pipefail

list=${1:?give a crib list}
if [ $# -ge 2 ]; then
  gcloud storage cp --quiet "$2" /tmp/judge.txt || { echo "could not fetch $2" >&2; exit 1; }
  judge=(--focus /tmp/judge.txt)
else
  judge=(--language de)
fi

while read -r word rest; do
  case $word in
    '' | '#'*) continue ;;
  esac
  echo "=== crib $word $rest"
  # shellcheck disable=SC2086
  ( time ./target/release/cb bombe data/ciphertext.txt --word "$word" $rest "${judge[@]}" --plain ) 2>&1
done < "$list"
