#!/usr/bin/env python3
import argparse
import os
from pathlib import Path
import socket
import subprocess
import tempfile


def run(command, **kwargs):
    print("+", " ".join(map(str, command)), flush=True)
    return subprocess.run(command, check=True, timeout=600, **kwargs)


def main():
    parser = argparse.ArgumentParser(description="Build, install, and check no-fault RPCs on Linux.")
    parser.add_argument("--build-dir", type=Path, default=Path("build"))
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    source = Path(__file__).resolve().parents[2]
    build = args.build_dir.resolve()
    run(["cmake", "-S", str(source), "-B", str(build),
         "-DCMAKE_BUILD_TYPE=Release", "-DBPFKI_BUILD_SMOKE_TEST=ON"])
    run(["cmake", "--build", str(build), "--parallel", str(args.jobs)])
    for name in ("bio-probe-test", "failkern-update-test"):
        run([str(build / "tests" / "smoke" / name)])
    with tempfile.TemporaryDirectory(prefix="bpfki-install-") as directory:
        prefix = Path(directory)
        run(["cmake", "--install", str(build), "--prefix", str(prefix)])
        binaries = ["bpfki", "time-chaos", "fail-bio", "fail-mount",
                    "fail-ext4-mount", "fail-alloc-page"]
        for name in binaries:
            executable = prefix / "bin" / name
            if not executable.is_file() or not os.access(executable, os.X_OK):
                raise RuntimeError(f"missing installed executable: {executable}")
            dependencies = run(["ldd", str(executable)], text=True, capture_output=True)
            print(dependencies.stdout, end="", flush=True)
            if "not found" in dependencies.stdout:
                raise RuntimeError(f"unresolved runtime dependency: {executable}")
        for name in ("clock_gettime", "gettimeofday"):
            expected = (source / "progs" / name).read_bytes()
            if (prefix / "bin" / name).read_bytes() != expected:
                raise RuntimeError(f"installed program differs: {name}")
            if (build / "bin" / name).read_bytes() != expected:
                raise RuntimeError(f"build program differs: {name}")
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        log = build / "smoke-service.log"
        with log.open("w") as output:
            service = subprocess.Popen(
                [str(prefix / "bin" / "bpfki"), "--host=127.0.0.1", f"--port={port}"],
                cwd=prefix / "bin", stdout=output, stderr=subprocess.STDOUT)
            try:
                run([str(build / "tests" / "smoke" / "bpfki-smoke"), f"127.0.0.1:{port}"])
                if service.poll() is not None:
                    raise RuntimeError(f"service exited with {service.returncode}")
            finally:
                service.terminate()
                try:
                    service.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    service.kill()
                    service.wait(timeout=5)
                print(log.read_text(), end="", flush=True)
    print("PASS: BIO guard policy, filter updates, build, install, dynamic libraries, and no-fault gRPC communication.")


if __name__ == "__main__":
    main()
