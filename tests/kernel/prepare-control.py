#!/usr/bin/env python3

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile


BASELINE = "2825d3832c9230ab6e26e8a47ed6de8d16ea5ae3"
SHIM = ["CMakeLists.txt", "src/CMakeLists.txt", "examples/CMakeLists.txt"]


def git(*args):
    return subprocess.check_output(["git", *args], timeout=30)


def main():
    runner = Path(os.environ["RUNNER_TEMP"])
    destination = runner / "bpfki-source-control-src"
    destination.mkdir(mode=0o700)
    with tempfile.TemporaryFile() as archive:
        subprocess.run(["git", "archive", BASELINE], stdout=archive, check=True, timeout=30)
        archive.seek(0)
        with tarfile.open(fileobj=archive) as source:
            source.extractall(destination, filter="data")
    for name in SHIM:
        shutil.copyfile(name, destination / name)
    evidence = {
        "baseline_revision": BASELINE,
        "candidate_revision": git("rev-parse", "HEAD").decode().strip(),
        "description": "Original runtime with candidate system-dependency build files. This is not a historical known-good binary.",
        "build_shim": SHIM,
        "runtime_files": {},
    }
    names = git("ls-tree", "-r", "--name-only", BASELINE, "src", "proto", "progs").decode().splitlines()
    for name in names:
        if name in SHIM:
            continue
        original = git("show", f"{BASELINE}:{name}")
        if (destination / name).read_bytes() != original:
            raise RuntimeError(f"source-control runtime changed: {name}")
        evidence["runtime_files"][name] = {
            "source_control_sha256": hashlib.sha256(original).hexdigest(),
            "candidate_sha256": hashlib.sha256(Path(name).read_bytes()).hexdigest(),
        }
    (runner / "bpfki-source-control.json").write_text(json.dumps(evidence, indent=2) + "\n")


if __name__ == "__main__":
    main()
