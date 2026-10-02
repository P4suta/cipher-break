#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Run `cb bombe` over a list of cribs, on the VM a job runs on.
#
#   bash cloud/jobs/cribs.sh <list> [gs://…/model.txt]
#
# One crib a line: the word, then any `cb bombe` flags for it, such as `--at 0 --right-rings`.
# Blank lines and lines starting with # are skipped.
# The judge is the quadgram model at the given URL if there is one, and German otherwise.
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
  # Word splitting of $rest is the point: it carries the flags.
  # shellcheck disable=SC2086
  ( time ./target/release/cb bombe data/ciphertext.txt --word "$word" $rest "${judge[@]}" --plain ) 2>&1
done < "$list"
