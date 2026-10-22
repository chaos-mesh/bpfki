# bpfki

bpfki is a BPF-based kernel fault injection service. It exposes gRPC methods for
SLAB allocation, page allocation, block I/O, and time fault requests. Chaos Mesh
uses its memory and block I/O RPCs for KernelChaos.

## Build and install

Build on Linux with CMake 3.18 or newer, a C++17 compiler, BCC, LLVM, protobuf,
gRPC, gflags, spdlog, and Abseil development packages. The top-level build uses
installed dependencies. It does not download or build third-party libraries.

On Ubuntu 24.04, install the build dependencies:

```sh
sudo apt-get update
sudo apt-get install --no-install-recommends -y \
  build-essential cmake pkg-config libbpfcc-dev llvm-dev \
  libprotobuf-dev protobuf-compiler protobuf-compiler-grpc libgrpc++-dev \
  libgflags-dev libspdlog-dev libabsl-dev python3
```

Configure, build, and install from the repository root:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel 2
cmake --install build --prefix "$PWD/install"
```

For dependencies in another prefix, pass `-DCMAKE_PREFIX_PATH=/path/to/prefix`
to CMake and configure the runtime linker to find their shared libraries. Use a
fresh build directory when switching from the former bundled build.

The build creates `build/bin/bpfki` and five clients in `build/examples`.
Installation places these files in `<prefix>/bin`:

- The `bpfki` service.
- The `time-chaos`, `fail-bio`, `fail-mount`, `fail-ext4-mount`, and
  `fail-alloc-page` clients.
- The `clock_gettime` and `gettimeofday` BPF program files.

## Run the service

Use an isolated Linux environment for the privileged injection service. The
service reads its BPF program files from its working directory. Run it from the
installed bin directory and bind the RPC listener to loopback:

```sh
cd install/bin
sudo ./bpfki --host=127.0.0.1 --port=50051
```

The examples issue real fault requests. Some examples ignore RPC errors and use
kernel-specific function names or device details. Their exit status does not
prove that injection or recovery worked. Inspect and adapt a request to the
actual kernel and target before using an example in a disposable test VM.

## Verify the build without injecting faults

Run the reproducible build and install check in a Linux environment with the
build dependencies installed:

```sh
python3 tests/smoke/verify.py --build-dir build --jobs 2
```

The script checks all installed executables and program files, resolves their
shared libraries, and starts a fresh service on loopback. Its client calls only
`RecoverMMOrBIO` and `RecoverTimeVal` with no active fault. It checks gRPC and
response status, then stops the service. Service output is saved in
`build/smoke-service.log`, and the temporary installation is removed.

This check proves packaging and communication. It does not load BPF programs
or verify kernel faults. The build workflow runs this check on native amd64
and arm64 runners.

## Qualify kernel faults in CI

The relevant running-kernel hooks are `should_failslab`,
`should_fail_alloc_page`, and `should_fail_bio`. BPF return override also needs
kernel support and error-injection permission for each hook. A new kernel or
root access alone does not establish these capabilities.

The kernel workflow first inspects the actual kernel configuration, matching
headers, hook symbols, and error-injection allowlist. Missing prerequisites
fail qualification with evidence. It then compares original runtime source
with the candidate on the same native amd64 runner. The original source uses
an explicit build shim and is not a historical known-good binary.

The private test driver limits faults to its own persistent non-root target
process. A separate control process must remain unaffected. BIO uses direct
reads from an owned read-only loop disk. Both injection cycles must observe
faults immediately before recovery and successful operations in the same
process afterward. RPCs, workers, and the whole run have deadlines and cleanup.

Compile the driver without running it:

```sh
cmake -S . -B build -DBPFKI_BUILD_KERNEL_TESTS=ON
cmake --build build --target kernel-tests --parallel 2
```

The runtime launcher accepts only a disposable GitHub-hosted Linux environment.
Do not bypass its guard or run it on a development machine, shared host, or
existing Kubernetes cluster. See [kernel test evidence](docs/kernel-tests.md)
for the exact operations, containment, artifacts, and verification limits.

## Protocol and source

[proto/bpfki.proto](proto/bpfki.proto) is the gRPC contract. Check both gRPC
status and response fields in clients. The protocol includes memory and BIO
injection and recovery, time requests, and syscall methods. A declared method
is not evidence that its behavior has been verified.

- [src/](src/) contains the service and generated BPF program construction.
- [progs/](progs/) contains the time BPF program files.
- [examples/](examples/) contains request examples.
- [tests/](tests/) contains packaging checks and the restricted kernel driver.
- [AGENTS.md](AGENTS.md) describes repository work and verification rules for agents.
