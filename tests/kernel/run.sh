#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 3 || ${GITHUB_ACTIONS:-} != true || ${RUNNER_ENVIRONMENT:-} != github-hosted ||
      ${RUNNER_OS:-} != Linux || ${RUNNER_TEMP:-} != /home/runner/work/_temp || $EUID == 0 ]]; then
  echo 'Usage on a disposable GitHub-hosted Linux runner: run.sh BASELINE_PREFIX CANDIDATE_PREFIX DRIVER' >&2
  exit 2
fi
output=$(mktemp -d "$RUNNER_TEMP/bpfki-kernel-XXXXXXXX")
chmod 700 "$output"
if [[ -n ${GITHUB_OUTPUT:-} ]]; then
  printf 'evidence=%s\n' "$output" >> "$GITHUB_OUTPUT"
fi
printf 'Evidence directory: %s\n' "$output"
finish() {
  status=$?
  trap - EXIT
  sudo chown -R "$(id -u):$(id -g)" "$output"
  exit "$status"
}
trap finish EXIT
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
keep=GITHUB_ACTIONS,RUNNER_ENVIRONMENT,RUNNER_OS,RUNNER_ARCH,RUNNER_NAME,RUNNER_TEMP,GITHUB_REPOSITORY,GITHUB_SHA,GITHUB_RUN_ID,GITHUB_RUN_ATTEMPT
sudo --preserve-env="$keep" python3 "$script_dir/probe.py" "$output" "$1" "$2"
timeout --kill-after=20s 540s sudo --preserve-env="$keep" "$3" "$1" "$2" "$output"
