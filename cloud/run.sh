#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Run one job on a throwaway Spot VM and leave nothing running afterwards.
#
#   cloud/run.sh <cpu|gpu> [--hours N] [--machine TYPE] [--standard] -- <command run in the repository on the VM>
#
# Spot by default.
# `--standard` pays the full price for a machine that is not taken back halfway: an L4 Spot VM was preempted seventeen minutes into a sweep.
#
# The working tree goes up as it is, uncommitted changes included, because the thing worth running is usually the thing not yet committed.
# The VM builds, runs the command, writes everything to the bucket, and deletes itself.
# If anything goes wrong on the way, `--max-run-duration` deletes it anyway: no failure leaves a machine billing.
set -euo pipefail

kind=${1:?cpu or gpu}
shift
hours=2
machine=""
model=SPOT
while [ $# -gt 0 ]; do
  case $1 in
    --hours) hours=$2; shift 2 ;;
    --machine) machine=$2; shift 2 ;;
    --standard) model=STANDARD; shift ;;
    --) shift; break ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
[ $# -gt 0 ] || { echo "give the command to run after --" >&2; exit 2; }

here=$(cd "$(dirname "$0")/.." && pwd)
project=$(gcloud config get-value project 2>/dev/null)
[ -n "$project" ] || { echo "no gcloud project set" >&2; exit 1; }
bucket="gs://$project-runs"
run_id="$(date -u +%Y%m%dT%H%M%SZ)-$kind"
name="cb-$(echo "$run_id" | tr 'A-Z' 'a-z')"

case $kind in
  gpu)
    machine=${machine:-g2-standard-8}
    zones=(us-west1-a us-central1-a us-central1-b us-central1-c us-east1-b us-east1-c us-east4-a asia-northeast1-a asia-northeast1-c)
    extra=(--accelerator=type=nvidia-l4,count=1)
    ;;
  cpu)
    machine=${machine:-c3d-highcpu-30}
    zones=(us-central1-a us-central1-b us-central1-c us-east1-b us-east1-c us-east4-a asia-northeast1-a asia-northeast1-b)
    extra=()
    ;;
  *) echo "kind is cpu or gpu" >&2; exit 2 ;;
esac

staging=$(mktemp -d)
trap 'rm -rf "$staging"' EXIT
# Tracked and untracked-but-not-ignored files, as they are on disk now.
(cd "$here" && COPYFILE_DISABLE=1 git ls-files -co --exclude-standard -z | tar czf "$staging/tree.tgz" --null -T -)
{
  echo "run      $run_id"
  echo "head     $(git -C "$here" rev-parse HEAD)"
  echo "diff     $(git -C "$here" diff HEAD | shasum -a 256 | cut -c1-16)"
  echo "machine  $machine ($kind, $model)"
  echo "command  $*"
} > "$staging/manifest.txt"
git -C "$here" diff HEAD > "$staging/uncommitted.diff"
printf '%s\n' "$*" > "$staging/job.sh"
gcloud storage cp --quiet "$staging"/* "$bucket/runs/$run_id/in/"

for zone in "${zones[@]}"; do
  echo "trying $machine in $zone"
  if gcloud compute instances create "$name" \
      --zone="$zone" \
      --machine-type="$machine" \
      ${extra[@]+"${extra[@]}"} \
      --provisioning-model="$model" \
      --instance-termination-action=DELETE \
      --max-run-duration="${hours}h" \
      --maintenance-policy=TERMINATE \
      --image-family=ubuntu-2404-lts-amd64 \
      --image-project=ubuntu-os-cloud \
      --boot-disk-size=60GB \
      --boot-disk-type=pd-balanced \
      --scopes=cloud-platform \
      --metadata="run-id=$run_id,bucket=$bucket,kind=$kind" \
      --metadata-from-file=startup-script="$here/cloud/startup.sh" \
      --quiet 2> "$staging/err"; then
    echo "$run_id started as $name in $zone"
    echo "watch: gcloud storage cat $bucket/runs/$run_id/out/log.txt"
    exit 0
  fi
  # Out of stock or out of quota in this zone: say which, and try the next.
  grep -E 'ERROR|message' "$staging/err" | head -2 >&2
done
echo "no zone would take $machine" >&2
exit 1
