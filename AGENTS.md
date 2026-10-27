# bpfki repository guide for agents

bpfki is a C++ gRPC service that uses BCC to inject kernel faults. Treat real
fault tests as privileged system operations. Read README.md and the relevant
source before changing behavior.

## Source ownership

- `CMakeLists.txt` owns system dependency discovery and the `bpfki_proto` target.
  It generates protocol sources once and adds service, example, and optional
  test targets.
- `src/` owns RPC handling and BPF program construction. `service.cc` manages
  injection instances; `bpfki.cc` builds and attaches probes.
- `proto/bpfki.proto` owns the wire contract. Generated protocol files belong in
  the build directory. Do not edit or commit generated files.
- `progs/` contains time program files. They must remain available beside the
  service in both `build/bin` and the installation bin directory because the
  service reads them relative to its working directory.
- `examples/` contains real fault clients, not verification programs.
- `tests/unit/` owns unit tests with fake BPF objects and simulated BCC calls.
- `.github/workflows/` owns native build and unit test checks.

## Work and build rules

Inspect `git status --short` before editing. Preserve unrelated changes and use
the user-requested branch or worktree. Do not modify another task's checkout.

Use the normal top-level CMake entry. Do not restore dependency downloads or
make downstream image consumers configure `src` and `examples` separately.
Keep dependency compatibility in bpfki. Keep image distribution and BCC version
selection in the consuming image repository.

Reuse existing shared package and Docker BuildKit caches. Do not create a new
language download cache for a task or worktree. Isolate source, build output,
and runtime state instead. Do not clear shared caches or run global Docker
prune commands.

Build and install from the repository root:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel 2
cmake --install build --prefix "$PWD/install"
```

The build requires Linux, CMake 3.18, a C++17 compiler, and the system development
packages listed in README.md, including LLVM headers used by the BCC C++ API.
Unit tests are disabled by default. Review install changes together with
executables, examples, and both program files.

## Verification

Configure and run the unit tests:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build build --parallel 2
ctest --test-dir build --output-on-failure
```

The tests must not load BPF programs, start a real RPC service, or inject faults.
Keep kernel operations behind the existing test seams. A unit test pass does
not prove real kernel injection or recovery.

Run `git diff --check` and the applicable build workflow. Record the actual
architecture and distinguish native execution from emulation. Do not claim CI
passed without an actual run.

## Kernel safety

Real fault injection requires an explicitly authorized, isolated Linux test
environment. A container shares its host kernel. Do not use a development
machine, shared host, or existing Kubernetes cluster for real fault tests.
Do not run example clients during unit tests. Keep any separately authorized
fault test limited to owned targets, with bounded duration and cleanup.

## Scope and delivery

Keep wire and runtime behavior changes separate from build modernization.
Record an original defect with evidence. If it blocks required verification,
report that gate as incomplete and propose a separate prerequisite fix.

Update README.md when commands, dependencies, installation, or supported
behavior change. Keep agent instructions about working in this repository,
not task history or temporary machine paths.

Create commits, push branches, and open PRs only with the user's explicit
authorization. Use `git commit --signoff` for DCO. Review the final diff before
committing, state the checks actually run, and leave merging or publishing to
the user's authorization.
