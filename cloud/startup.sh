#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -uo pipefail

meta() { curl -sf -H 'Metadata-Flavor: Google' "http://metadata.google.internal/computeMetadata/v1/$1"; }
run_id=$(meta instance/attributes/run-id)
bucket=$(meta instance/attributes/bucket)
kind=$(meta instance/attributes/kind)
zone=$(meta instance/zone | sed 's|.*/||')
name=$(meta instance/name)
out="$bucket/runs/$run_id/out"
work=/opt/job
log=$work/log.txt
mkdir -p "$work"
exec > >(tee -a "$log") 2>&1

finish() {
  echo "$1" > "$work/status"
  echo "=== finished: $1 at $(date -u +%FT%TZ)"
  gcloud storage cp --quiet "$work/log.txt" "$work/status" "$out/"
  gcloud compute instances delete "$name" --zone="$zone" --quiet || poweroff
  exit 0
}

( while sleep 60; do gcloud storage cp --quiet "$log" "$out/log.txt" 2>/dev/null; done ) &

echo "=== $run_id on $(meta instance/machine-type | sed 's|.*/||') in $zone, $(nproc) threads"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q && apt-get install -yq build-essential pkg-config curl || finish "apt failed"

if [ "$kind" = gpu ]; then
  apt-get install -yq ubuntu-drivers-common libvulkan1 vulkan-tools "linux-headers-$(uname -r)" || finish "apt failed"
  ubuntu-drivers list
  ubuntu-drivers install || finish "driver install failed"
  modprobe nvidia || { dkms autoinstall && modprobe nvidia; } || finish "the driver would not load"
  nvidia-smi || finish "nvidia-smi failed"
  vulkaninfo --summary 2>&1 | grep -E 'deviceName|driverName' || finish "no Vulkan device"
  features="--features gpu"
else
  features=""
fi

cd "$work"
gcloud storage cp --quiet "$bucket/runs/$run_id/in/*" . || finish "download failed"
mkdir repo && tar xzf tree.tgz -C repo || finish "unpack failed"
cat manifest.txt

export HOME=/root CARGO_HOME=/root/.cargo RUSTUP_HOME=/root/.rustup
curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none || finish "rustup failed"
source /root/.cargo/env
cd repo
rustup toolchain install || finish "toolchain install failed"
echo "=== build"
cargo build --release $features || finish "build failed"
./target/release/cb devices

echo "=== job: $(cat ../job.sh)"
start=$(date +%s)
CB_FEATURES="$features" bash ../job.sh
code=$?
echo "=== job exit $code after $(( $(date +%s) - start ))s"
finish "exit $code"
