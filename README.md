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

For memory and block I/O requests, `probability` must be finite and between `0`
and `1`. Zero, including an omitted value, disables injection; `1` injects at
every eligible hook. This corrects the former behavior where zero enabled
unconditional injection. The fault examples explicitly use `1` by default.
`times=0` keeps injection active until recovery; a positive value limits the
number of hook injections, which need not equal the number of system calls.
These rules do not apply to time requests.

BIO requests require this service's live `should_fail_bio` entry probe to use
`FTRACE`, with no `OPTIMIZED`, `DISABLED`, or `GONE` mode. The service checks its
own perf FD, BPF program and `ctxs` map identity, and the probe's actual address
before enabling a filter and before every later BIO update. Plain kprobes are
rejected even when optimization has not happened yet. This is a conservative
support limit. Some non-FTRACE kernels may support BIO injection, but that path
has not been qualified here.

The administrator must provide readable `/proc/self/fd` and
`/sys/kernel/debug/kprobes/list`, and permission to query BPF object and perf FD
metadata. A container that cannot see the host's kprobes metadata cannot pass
this check. The current Chaos Mesh Helm bpfki container does not mount host
debugfs. BIO requests return `FAILED_PRECONDITION` when that deployment cannot
read this metadata. bpfki does not mount debugfs or change global kernel controls.
Missing, unreadable, ambiguous, or incompatible metadata returns gRPC
`FAILED_PRECONDITION` with the reason before changing filters. A new rejected
instance is discarded. A rejected update preserves existing filters for
recovery. SLAB, PAGE, and time requests do not require this BIO metadata.

Legacy `FailMMOrBIO` requests with the same callchain reuse an injection instance.
Changing its fault type requires recovery first; otherwise the request returns
`FAILED_PRECONDITION`. Recovery keeps the callchain-based lookup, accepts an
omitted fault type, and does not require BIO metadata.

## Recover owned kernel faults after process restarts

Use `ReserveKernelFault`, `ArmKernelFault`, and `ReleaseKernelFault` for memory
and BIO faults that need recovery after a target or controller restart. Each
handle owns a separate BPF instance and random probe event namespace, including
when handles have the same PID and callchain. Legacy instances also have their
own probe event namespaces. The legacy RPCs keep their callchain and PID lookup.

1. Send the current node boot ID and a fault request to `ReserveKernelFault`.
   The request requires a positive PID, `tid=0`, a supported fault type, and a
   finite probability between `0` and `1`. Only the last callchain frame may
   omit its function name. Reserve saves the target process start time from
   `/proc` and rejects an absent target. It does not create or load a BPF object.
2. Persist the complete returned handle, including its session, together with
   the original node identity and service address before calling `ArmKernelFault`.
   Repeat Arm with that handle after an uncertain reply. A repeated successful
   Arm preserves the filter and its injection counter. First Arm checks the
   saved target start time before initialization and again before the filter
   write. A missing target or a reused PID returns `NOT_FOUND` without enabling
   the fault. Unreadable process metadata returns an error.
3. Call `ReleaseKernelFault` with the saved handle and current boot ID of the
   original node. Release destroys only that handle's BPF instance. It does not
   need the target PID or a running target process. Repeated Release returns
   `ABSENT`, and a later Arm returns `NOT_FOUND`.

Instance destruction closes its perf FDs before destroying its BPF programs and
maps. It attempts to remove every event it tried to attach, including failed
attempts. Cleanup errors are logged. Release does not return tracefs deletion
errors, so a successful reply does not prove that all tracefs entries were removed.

Unarmed reservations expire after five minutes. Lifecycle RPCs collect expired
reservations, and at most 1024 unarmed reservations can remain pending. Armed
reservations do not expire. Arm cannot recreate a missing reservation. Retire
an expired handle before reserving and persisting a new one.

The session records a random service instance, node boot ID, service PID,
process start time, and PID namespace. New RPCs reject a current node boot ID
that differs from the server's boot ID. Arm rejects another service instance
with `ABORTED`. A replacement service returns `SERVICE_GONE` from Release only
after a node reboot or proof that the original service process has ended.
For the same boot, proof requires the same PID namespace and a missing process
or a different process start time. A live process, unreadable metadata, or a
different PID namespace returns an error and preserves the recovery obligation.
Clients must verify the original node identity before accepting this proof.

The service requires readable boot and process metadata in `/proc`, with procfs
mounted for its PID namespace. Service replacements in separate private PID
namespaces cannot prove each other's termination. Deployments that need this
proof must use the same host PID namespace and procfs view.

Older servers return `UNIMPLEMENTED` for these methods. Do not fall back to
legacy PID recovery or treat an injected record without a saved handle as
recovered. These handles protect recovery ownership when PIDs are reused.
The process checks do not pin the target lifetime. A process can exit between
the final check and filter write. Active BPF filters still match numeric PIDs
and can match a reused PID before cleanup.

## Run unit tests

Enable and run the unit tests in a Linux build environment:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build build --parallel 2
ctest --test-dir build --output-on-failure
```

The four test programs cover BIO support checks, filter updates, owned fault
lifecycles, and probe ownership. They substitute BPF objects, BCC calls, or
kernel metadata as needed. They do not load BPF programs, start an RPC server,
or inject faults. The build workflow runs them on native amd64 and arm64 runners.
Unit tests are disabled by default.

## Protocol and source

[proto/bpfki.proto](proto/bpfki.proto) is the gRPC contract. Check both gRPC
status and response fields in clients. The protocol includes memory and BIO
injection and recovery, time requests, and syscall methods. A declared method
is not evidence that its behavior has been verified.

- [src/](src/) contains the service and generated BPF program construction.
- [progs/](progs/) contains the time BPF program files.
- [examples/](examples/) contains request examples.
- [tests/unit/](tests/unit/) contains the unit tests.
- [AGENTS.md](AGENTS.md) describes repository work and verification rules for agents.
