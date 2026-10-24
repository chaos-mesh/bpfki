#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 2 || $(uname -s) != Linux || $(uname -m) != x86_64 ]]; then
  echo 'Usage on Linux amd64: build-rootfs.sh KERNEL_TREE OUTPUT_DIRECTORY' >&2
  exit 2
fi
kernel=$(realpath "$1")
mkdir -p "$2"
output=$(realpath "$2")
repo=$(git rev-parse --show-toplevel)
context=$(mktemp -d)
container=
cleanup() {
  [[ -z $container ]] || docker rm "$container" >/dev/null
  sudo rm -rf -- "$context"
}
trap cleanup EXIT
mkdir "$context/candidate"
cp -a "$repo"/{CMakeLists.txt,src,proto,progs,examples,tests} "$context/candidate/"
cp -a "$RUNNER_TEMP/bpfki-source-control-src" "$context/source-control"
cp "$RUNNER_TEMP/bpfki-source-control.json" "$context/provenance.json"
docker build --progress=plain -f "$repo/tests/kernel/vm/Dockerfile" \
  -t bpfki-kernel-rootfs:ci "$context"
container=$(docker create bpfki-kernel-rootfs:ci)
mkdir "$context/rootfs"
docker export "$container" | sudo tar -xpf - -C "$context/rootfs"
release=$(cat "$kernel/bpfki-kernel-release")
sudo cp "$kernel/.config" "$context/rootfs/boot/config-$release"
sudo mkdir -p "$context/rootfs/lib/modules/$release"
sudo ln -s /kernel-headers "$context/rootfs/lib/modules/$release/build"
sudo ln -s /kernel-headers "$context/rootfs/lib/modules/$release/source"
python3 - "$context/ci.env" <<'ENV'
import os, shlex, sys
keys = ["GITHUB_ACTIONS", "RUNNER_ENVIRONMENT", "RUNNER_OS", "RUNNER_ARCH",
        "RUNNER_NAME", "RUNNER_TEMP", "GITHUB_REPOSITORY", "GITHUB_SHA",
        "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"]
with open(sys.argv[1], "w") as target:
    for key in keys:
        target.write(f"export {key}={shlex.quote(os.environ[key])}\n")
ENV
sudo cp "$context/ci.env" "$context/rootfs/etc/bpfki-ci.env"
truncate -s 5G "$output/rootfs.ext4"
sudo mkfs.ext4 -q -F -d "$context/rootfs" "$output/rootfs.ext4"
