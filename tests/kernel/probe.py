#!/usr/bin/env python3

import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: probe.py OUTPUT BASELINE_PREFIX CANDIDATE_PREFIX")
    output = Path(sys.argv[1]).resolve(strict=True)
    runner = Path(os.environ.get("RUNNER_TEMP", "/missing")).resolve(strict=True)
    uid = int(os.environ.get("SUDO_UID", "0"))
    if (os.geteuid() != 0 or uid == 0
            or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or os.environ.get("RUNNER_OS") != "Linux"
            or str(runner) != "/home/runner/work/_temp"
            or output.parent != runner or not output.name.startswith("bpfki-kernel-")
            or output.stat().st_uid != uid or output.stat().st_mode & 0o777 != 0o700):
        raise SystemExit("requires an owned directory on a disposable GitHub-hosted Linux runner")
    release = platform.release()
    failures = []
    evidence = {
        "kernel": release,
        "uname": list(platform.uname()),
        "native_architecture": platform.machine(),
        "runner": {key: os.environ.get(key) for key in
                   ["RUNNER_NAME", "RUNNER_OS", "RUNNER_ARCH", "RUNNER_ENVIRONMENT",
                    "GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"]},
        "required_hooks": {"should_failslab": "ERRNO", "should_fail_alloc_page": "TRUE",
                           "should_fail_bio": "ERRNO"},
        "expected_syscall_errors": {"SLAB": "ENOMEM", "PAGE": "ENOMEM", "BIO": "EIO"},
        "failures": failures,
    }
    if platform.machine() != "x86_64" or os.environ.get("RUNNER_ARCH") != "X64":
        failures.append("the first runtime gate requires native amd64")
    config_file = Path(f"/boot/config-{release}")
    if config_file.is_file():
        config = config_file.read_text()
    elif Path("/proc/config.gz").is_file():
        config_file = Path("/proc/config.gz")
        with gzip.open(config_file, "rt") as source:
            config = source.read()
    else:
        config = ""
        failures.append("running kernel configuration is unavailable")
    evidence["config_path"] = str(config_file)
    evidence["config_sha256"] = hashlib.sha256(config.encode()).hexdigest()
    (output / "kernel.config").write_text(config)
    required = ["BPF", "BPF_SYSCALL", "KPROBES", "BPF_KPROBE_OVERRIDE",
                "FUNCTION_ERROR_INJECTION", "FAULT_INJECTION", "FAILSLAB",
                "FAIL_PAGE_ALLOC", "DEBUG_FS", "BLOCK"]
    values = dict(re.findall(r"^CONFIG_(\w+)=(.*)$", config, re.MULTILINE))
    evidence["required_config"] = {key: values.get(key, "unset") for key in required}
    evidence["global_bio_fault_config"] = values.get("FAIL_MAKE_REQUEST", "unset")
    for key in required:
        if values.get(key) != "y":
            failures.append(f"CONFIG_{key}=y is required")
    if not Path("/sys/module/loop").is_dir() or not Path("/dev/loop-control").exists():
        failures.append("loop driver must already be loaded; the tests do not load modules")
    headers = Path(f"/lib/modules/{release}/build")
    release_header = headers / "include/generated/utsrelease.h"
    evidence["headers"] = str(headers.resolve())
    if not release_header.is_file() or f'"{release}"' not in release_header.read_text():
        failures.append("matching running-kernel headers are unavailable")
    roots = [headers, Path(f"/lib/modules/{release}/source"),
             Path("/usr/src") / ("linux-headers-" + release.rsplit("-", 1)[0])]
    header_checks = {
        "bio.bi_bdev": (r"struct\s+block_device\s*\*\s*bi_bdev\s*;",
                        ["include/linux/blk_types.h", "include/linux/bio.h"]),
        "block_device.bd_dev": (r"\bdev_t\s+bd_dev\s*;",
                                ["include/linux/blk_types.h", "include/linux/blkdev.h", "include/linux/fs.h"]),
        "MKDEV": (r"#define\s+MKDEV\(", ["include/linux/kdev_t.h"]),
    }
    evidence["bio_headers"] = {}
    for field, (pattern, names) in header_checks.items():
        found = next((root / name for root in roots for name in names
                      if (root / name).is_file() and re.search(pattern, (root / name).read_text())), None)
        if found:
            evidence["bio_headers"][field] = {"path": str(found.resolve()), "sha256": digest(found)}
        else:
            failures.append(f"required BIO field or macro is unavailable: {field}")
    symbols = Path("/proc/kallsyms").read_text()
    allowlist_path = Path("/sys/kernel/debug/error_injection/list")
    allowlist = allowlist_path.read_text() if allowlist_path.is_file() else ""
    evidence["allowlist_path"] = str(allowlist_path)
    (output / "error-injection-list.txt").write_text(allowlist)
    evidence["hooks"] = {}
    for hook, allowed in evidence["required_hooks"].items():
        symbol_lines = [line for line in symbols.splitlines()
                        if len(line.split()) >= 3 and line.split()[2] == hook]
        allowed_lines = [line for line in allowlist.splitlines()
                         if line.split() and line.split()[0] == hook]
        evidence["hooks"][hook] = {"symbols": symbol_lines, "allowed_returns": allowed_lines}
        if not symbol_lines:
            failures.append(f"running kernel has no {hook} symbol")
        if not any(line.split()[-1] == allowed for line in allowed_lines):
            failures.append(f"{hook} is not allowlisted for {allowed}")
    evidence["packages"] = subprocess.run(
        ["dpkg-query", "-W", "libbpfcc-dev", "libbpfcc", "libgrpc++-dev", "libprotobuf-dev",
         "clang", "gcc", "g++"], capture_output=True, text=True, timeout=10).stdout
    evidence["installations"] = {}
    for name, argument in zip(["source_control", "candidate"], sys.argv[2:]):
        prefix = Path(argument).resolve(strict=True)
        files = [prefix / "bin" / item for item in ["bpfki", "clock_gettime", "gettimeofday"]]
        evidence["installations"][name] = {str(path): digest(path) for path in files}
    provenance = runner / "bpfki-source-control.json"
    if provenance.is_file():
        evidence["source_control"] = json.loads(provenance.read_text())
    else:
        failures.append("source-control build provenance is missing")
    evidence["outcome"] = "unsupported" if failures else "qualified"
    (output / "environment.json").write_text(json.dumps(evidence, indent=2) + "\n")
    if failures:
        (output / "summary.json").write_text(json.dumps({
            "passed": False, "outcome": "unsupported", "faults_verified": False,
            "failures": failures}, indent=2) + "\n")
        print("UNSUPPORTED: " + "; ".join(failures), file=sys.stderr)
        return 2
    (output / "qualified-kernel").write_text(release + "\n")
    print("Kernel prerequisites qualified. No BPF program has been loaded by this probe.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
