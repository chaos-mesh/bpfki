#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 1 || $(uname -s) != Linux || $(uname -m) != x86_64 ]]; then
  echo 'Usage on Linux amd64: build-kernel.sh SHARED_CACHE' >&2
  exit 2
fi
cache=$(realpath -m "$1")
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
version=6.8
sha256=c969dea4e8bb6be991bbf7c010ba0e0a5643a3a8d8fb0a2aaa053406f1e965f3
mkdir -p "$cache"
archive="$cache/linux-$version.tar.xz"
if [[ ! -f $archive ]]; then
  curl --fail --location --retry 3 --max-time 300 \
    "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$version.tar.xz" -o "$archive.part"
  mv "$archive.part" "$archive"
fi
printf '%s  %s\n' "$sha256" "$archive" | sha256sum --check --status
fingerprint=$({ sha256sum "$script_dir/kernel.config" "$script_dir/build-kernel.sh"; gcc --version; ld --version; } | sha256sum | cut -d' ' -f1)
kernel="$cache/linux-$version"
if [[ -f $kernel/.bpfki-complete && $(cat "$kernel/.bpfki-complete") == "$fingerprint" ]]; then
  test -s "$kernel/arch/x86/boot/bzImage"
  exit 0
fi
if [[ ! -d $kernel ]]; then
  tar -xJf "$archive" -C "$cache"
fi
export KBUILD_BUILD_TIMESTAMP='2024-03-10 00:00:00 UTC'
export KBUILD_BUILD_USER=bpfki KBUILD_BUILD_HOST=github-ci
make -C "$kernel" x86_64_defconfig
(cd "$kernel" && scripts/kconfig/merge_config.sh -m .config "$script_dir/kernel.config")
make -C "$kernel" olddefconfig
while IFS= read -r option; do
  if [[ $option == CONFIG_*=y || $option == CONFIG_LOCALVERSION=* ]]; then
    grep -Fxq "$option" "$kernel/.config" || { echo "Missing required kernel option: $option" >&2; exit 1; }
  fi
done < "$script_dir/kernel.config"
make -C "$kernel" -j"$(nproc)" bzImage
make -s -C "$kernel" kernelrelease > "$kernel/bpfki-kernel-release"
printf '%s\n' "$fingerprint" > "$kernel/.bpfki-complete"
