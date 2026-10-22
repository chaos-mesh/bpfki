#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 2 || ${GITHUB_ACTIONS:-} != true || ${RUNNER_ENVIRONMENT:-} != github-hosted ||
      ${RUNNER_OS:-} != Linux || ${RUNNER_ARCH:-} != X64 ||
      ${RUNNER_TEMP:-} != /home/runner/work/_temp || $EUID == 0 ]]; then
  echo 'Usage on a disposable GitHub-hosted amd64 runner: vm/run.sh KERNEL_TREE OUTPUT_DIRECTORY' >&2
  exit 2
fi
kernel=$(realpath "$1")
output=$(realpath "$2")
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
acceleration=tcg
if [[ -r /dev/kvm && -w /dev/kvm ]]; then
  acceleration=kvm
fi
printf '%s\n' "$acceleration" | tee "$output/acceleration.txt"
cp "$kernel/.config" "$output/kernel.config"
cp "$kernel/bpfki-kernel-release" "$output/kernel-release.txt"
set +e
timeout --kill-after=20s 720s qemu-system-x86_64 \
  -machine q35,accel="$acceleration" -cpu max -m 3072 -smp 2 \
  -nodefaults -no-reboot -display none -monitor none -serial stdio -nic none \
  -kernel "$kernel/arch/x86/boot/bzImage" \
  -append 'console=ttyS0 root=/dev/vda rw init=/opt/bpfki/tests/kernel/vm/init.sh panic=1 oops=panic' \
  -drive "file=$output/rootfs.ext4,format=raw,if=virtio" \
  -virtfs "local,path=$kernel,mount_tag=kernel-headers,security_model=none,readonly=on" \
  > "$output/serial.log" 2>&1
qemu_status=$?
set -e
printf '%s\n' "$qemu_status" > "$output/qemu-exit-code.txt"
python3 "$script_dir/read-result.py" "$output"
