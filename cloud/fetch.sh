#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Bring a run's results home, or list the runs when no id is given.
set -euo pipefail

project=$(gcloud config get-value project 2>/dev/null)
bucket="gs://$project-runs"
here=$(cd "$(dirname "$0")/.." && pwd)

if [ $# -eq 0 ]; then
  gcloud storage ls "$bucket/runs/"
  exit 0
fi
dest="$here/reports/cloud/$1"
mkdir -p "$dest"
gcloud storage cp --quiet -r "$bucket/runs/$1/*" "$dest/"
cat "$dest/out/status" 2>/dev/null || echo "not finished yet"
echo "in $dest"
