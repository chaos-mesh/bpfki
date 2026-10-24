#!/usr/bin/env bash
set -euo pipefail

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev || mountpoint -q /dev
mkdir -p /dev/pts /run /sys/kernel/debug
mount -t devpts devpts /dev/pts
mount -t tmpfs tmpfs /run
output=/home/runner/work/_temp
finish() {
  status=$?
  trap - EXIT
  set +e
  printf '{"exit_code":%d}\n' "$status" > "$output/vm-result.json"
  tar -czf /run/evidence.tar.gz -C "$output" .
  if [[ $? == 0 ]]; then
    printf '\nBPFKI_EVIDENCE_BEGIN\n'
    base64 /run/evidence.tar.gz
    printf 'BPFKI_EVIDENCE_END\n'
  fi
  sync
  /bin/busybox poweroff -f
}
trap finish EXIT
mount -t debugfs debugfs /sys/kernel/debug
mount -t 9p -o trans=virtio,version=9p2000.L,ro kernel-headers /kernel-headers
ip link set lo up
source /etc/bpfki-ci.env
export GITHUB_OUTPUT=/home/runner/work/_temp/launcher-output
runuser --preserve-environment -u runner -- bash /opt/bpfki/tests/kernel/run.sh \
  /opt/control /opt/candidate /opt/kernel-tests
