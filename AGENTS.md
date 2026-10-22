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
- `tests/smoke/` owns build, installation, library, and no-fault RPC checks.
- `tests/kernel/` owns fixed workloads, process and disk containment, capability
  qualification, and original-source comparison.
- `.github/workflows/` separates native build checks from real kernel tests.

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
packages listed in README.md. Production targets do not enable either test
option by default. Review install changes together with executables, examples,
and both program files.

## Verification

For build, dependency, or packaging changes, run the no-fault check:

```sh
python3 tests/smoke/verify.py --build-dir build --jobs 2
```

It builds and installs all executables, checks shared libraries and resource
contents, and verifies recovery RPC communication with no active fault. Report
these results as packaging and communication only.

For kernel-driver changes, compile it without executing it locally:

```sh
cmake -S . -B build -DBPFKI_BUILD_KERNEL_TESTS=ON
cmake --build build --target kernel-tests --parallel 2
```

Run the focused checks for the changed layer, `git diff --check`, and the
applicable GitHub workflow. Record the actual architecture and distinguish
native execution from emulation. Do not claim CI passed without an actual run.

## Kernel test boundary

Real BPF loading and fault injection belong only in the dedicated workflow on
a fresh GitHub-hosted Linux VM. Never bypass the launcher guard, add a local or
self-hosted override, use an existing user Kubernetes cluster, or run example
fault clients during a local smoke check. A container does not isolate its
host kernel.

The harness must own its target and control processes. Workers run as non-root.
Keep exact PID identity checks, RPC deadlines, operation limits, the watchdog,
and service-first cleanup. Do not accept arbitrary target PIDs, device paths,
BPF predicates, or shell commands as test inputs.

BIO uses only the harness-created sparse loop disk and read-only direct I/O.
Verify the actual loop backing file and device identity. Do not write physical
disks, mount test filesystems, change global fault controls, load kernel modules,
or change or reboot the host kernel. Detach only the device created by the run.

Capability qualification must inspect actual headers, symbols, configuration,
and return-type allowlists. Unsupported prerequisites fail explicitly with
artifacts. Do not convert an unsupported or failed mandatory case into a green
skip, weaken assertions, or tune request frames around a production defect.

A functional pass needs successful baseline operations, observed target errors,
an unaffected control, an active fault immediately before recovery, successful
operations in the same target afterward, a repeat cycle, and cleanup. Neither a
successful RPC nor an exhausted injection count proves recovery. See
`docs/kernel-tests.md` for the exact sequence and evidence files.

## Scope and delivery

Keep wire and runtime behavior changes separate from build modernization.
Record an original defect with evidence. If it blocks required verification,
report that gate as incomplete and propose a separate prerequisite fix. An old
source build with new build files is a source control, not a historical
known-good release.

Update README.md when commands, dependencies, installation, or supported
behavior change. Keep agent instructions about working in this repository,
not task history or temporary machine paths.

Create commits, push branches, and open PRs only with the user's explicit
authorization. Use `git commit --signoff` for DCO. Review the final diff before
committing, state the checks actually run, and leave merging or publishing to
the user's authorization.
