# Kernel test evidence

The `Kernel fault qualification` workflow runs on a fresh `ubuntu-24.04` GitHub-hosted VM. Runtime qualification starts with native amd64. The separate build workflow compiles the private kernel driver on native amd64 and arm64. Its smoke check executes only no-fault communication checks and never runs the kernel driver.

The runtime workflow compares the candidate with runtime source from `2825d3832c9230ab6e26e8a47ed6de8d16ea5ae3`. Both use the same installed dependencies and current CMake build files. The artifact records the build shim and hashes every original runtime source file. This is a source control, not a historical known-good binary.

## Execution boundary

`tests/kernel/run.sh` accepts two installation prefixes and the built private driver. It creates its evidence directory under `/home/runner/work/_temp`. Both the launcher and driver require the GitHub-hosted Linux environment. There is no local or self-hosted override. The environment checks prevent accidental misuse and do not authenticate the host.

The capability probe reads the running kernel configuration, matching headers, hook symbols, and `/sys/kernel/debug/error_injection/list`. It requires the allowed return types for `should_failslab`, `should_fail_alloc_page`, and `should_fail_bio`. It also verifies the BIO device fields and that the loop driver is already loaded. Missing capabilities produce an `unsupported` result. Only exit code 2 together with that recorded outcome permits the workflow to try the disposable guest below. Any host assertion failure fails the job without a fallback. The probe does not load BPF, mount debugfs, change fault controls, or load kernel modules.

The driver owns the service and both persistent workers. Workers drop root privileges, clear supplementary groups, and set `no_new_privs` before execution. Pidfds bind supervision to the owned processes. PID and `/proc` start time are checked before operations and RPCs. Results use preallocated shared memory, so fault injection does not need a successful allocation to report its result.

## Disposable guest fallback

When the hosted kernel lacks required hooks, the workflow builds Linux 6.8 from a SHA-256-verified kernel.org archive. `tests/kernel/vm/kernel.config` enables the required fault hooks, built-in loop driver, virtio root disk, and 9p headers share. The cache key includes the version, architecture, build environment, configuration, and build script. The build also verifies its compiler fingerprint before reusing a completed kernel.

The guest requests `FUNCTION_TRACER` and `DYNAMIC_FTRACE`. Before boot, the workflow requires their resolved values, `DYNAMIC_FTRACE_WITH_REGS`, `KPROBES_ON_FTRACE`, and `OPTPROBES` to be enabled. It does not disable jump optimization globally. A passing guest also needs the actual owned BIO probe to report `FTRACE`, with no `OPTIMIZED`, `DISABLED`, or `GONE` flag, before and after its finite operation. Configuration bits alone do not establish that attachment mode.

The workflow builds the source control, candidate, and unchanged test driver in an Ubuntu 24.04 root filesystem with distro BCC and LLVM development headers. It creates the ext4 image with `mkfs.ext4 -d`, without mounting it on the host. QEMU receives only that disposable image and a read-only share of the matching kernel source and generated headers. It has no network device or host block device. The guest boots its own kernel without changing or rebooting the host.

The guest mounts its own debugfs and invokes the existing `tests/kernel/run.sh` as the non-root `runner` account. The workflow forwards its CI identity variables. The same launcher guards, capability checks, fixtures, and fault assertions apply. The guest has 3 GiB of RAM, two CPUs, and a 720-second outer deadline. `acceleration.txt` records KVM when the runner can access it, otherwise TCG emulation. Guest architecture does not imply native execution.

The guest returns its evidence archive over the serial console before powering off. The host requires a complete archive, qualification evidence, a test summary, and the actual guest exit status. Unsupported guest prerequisites, failed assertions, missing results, or QEMU timeout fail the job. Host and guest evidence are uploaded together, and the disposable disk is removed. A guest pass verifies the pinned guest kernel only.

## Assertions

Each candidate fault case keeps the same service, target, and control processes throughout the case. Both workers first complete a baseline operation. Before the two unlimited injection cycles, the driver replaces the condition on the same loaded BPF map with these profiles.

1. Probability zero and unlimited count must permit a normal target operation. The actual map counter must be zero before and after it.
2. Probability one and count one must cause a target error and leave the actual counter at one. A subsequent normal target operation must leave the counter at one.
3. Probability one and unlimited count must reset the actual counter to zero before the first unlimited cycle.

The profiles reuse the unchanged callchain and loaded map. They do not add BPF compilations. A worker operation can invoke a hook more than once, so counter assertions use actual map reads rather than syscall counts.

Each unlimited cycle requires the following sequence.

1. The generated gRPC client injects into the target PID and checks transport status and `response.ret`. The actual initial map threshold must be `4294967296`, the limit zero, and the counter zero.
2. The target reports the expected error. The control completes its operation.
3. The target reports the expected error again immediately before recovery.
4. Recovery sends the exact injection request. The same target process and the control complete their operations.

The second injection and recovery cycle repeats these assertions, including the initial map state.

In candidate SLAB cycle one, the driver also submits probability two after the first fault and normal control operation. It requires an explicit error response, excluding transport timeouts or disconnection. Actual map bytes and map identity must remain unchanged. The existing pre-recovery error then proves that the active filter remains effective. Recovery and reinjection must still pass.

Every request uses one direct-hook predicate frame. Candidate probability zero means no injection, including an omitted proto3 probability. Probability one means all eligible hooks. Count zero means unlimited. The pre-recovery errors reject counter exhaustion as evidence of recovery.

The source control must reproduce the exact known layout defect for SLAB, PAGE, and BIO. `prepare-control.py` verifies its original runtime files against the pinned revision. The capability probe requires that revision, the exact build shim, and fixed original runtime hashes before recording qualification. Each case requires both successful baseline operations, the old 40-byte map shape, initial fields `0,1,0`, a target error, a normal control, and an unexpected normal pre-recovery target operation. Actual map reads after both target operations must show `0,1,1`. Process identities must remain unchanged and cleanup must pass. This result is `known_layout_bug_reproduced`, with `functional_pass=false`. Any other source-control failure fails the comparison.

For every map capture, the driver discovers map IDs only through the owned service's `/proc/PID/fdinfo` entries. It opens a read-only descriptor and verifies the returned metadata length, map name, hash type, and four-byte key. It requires one distinct `ctxs` map with an exact versioned shape. The source control uses 40 bytes and native `u32` fields at offsets 0, 4, and 8. The candidate uses the indices and size from `src/filter_layout.h`, with 56 bytes for this single-frame request. Service and target identities and the service's map descriptor association are checked around the lookup. Missing or ambiguous provenance fails the case.

Each `filter_map` event records the profile, schema version, service PID and start time, descriptor path, map ID, map shape, target key, field offsets, decoded condition and counter, and raw value bytes. These reads do not modify maps or replace fault and recovery assertions.

Candidate BIO also records two read-only `owned_probe` snapshots around its existing finite operation. Discovery is limited to perf descriptors held by the owned service. `BPF_TASK_FD_QUERY` must identify the exact logical `should_fail_bio` entry and a matching program descriptor. The kprobes status row must match that queried address; exact symbol offsets zero and four accommodate x86 entry normalization. Both snapshots record stable process and descriptor identities, the operation sequence, raw status and diagnostic gaps. Each capture has a 250 ms soft collection deadline, at most 256 service descriptors, 4 KiB per fdinfo file and 64 KiB per status file. The soft deadline cannot interrupt an in-flight kernel call; the existing watchdog remains the outer bound. `OPTIMIZED` may include queued optimization and does not prove the exact instruction path of a hit.

The fixed worker operations are bounded.

| Fault | Target and control operation | Required error |
| --- | --- | --- |
| SLAB | Open and close `/dev/null`. | `ENOMEM` |
| PAGE | Write 4 KiB to a fresh nonblocking pipe. Pipe descriptors and the user buffer exist before injection. | `ENOMEM` |
| BIO | Read 4 KiB with `O_DIRECT` from the dedicated read-only loop disk. | `EIO` |

The BIO file is an 8 MiB sparse file owned by the driver. The driver attaches it read-only, validates its inode and loop device identity, and builds the predicate from the real device major and minor numbers. The predicate uses `bio->bi_bdev->bd_dev`. Successful BIO operations must also advance the loop device's read completion count. The tests do not mount filesystems or write block devices.

## Deadlines and cleanup

Injection RPCs have 45-second deadlines to allow on-demand BPF compilation under TCG. Recovery RPCs have 10-second deadlines. Worker readiness and operations have 3-second deadlines. Each candidate target performs ten operations and its control performs five. Each source-control target performs three operations and its control performs two. Every worker retains the hard limit of sixteen operations. Each case has a separate 75-second watchdog, and the comparison has an 8-minute deadline. The launcher adds a 540-second outer timeout with a 20-second termination grace period. The job timeout also bounds setup and compilation.

On a case failure, the driver kills and reaps its service first to detach probes, then stops both workers and the watchdog. The watchdog uses pidfds to enforce the same order on timeout or parent death. Service and worker processes also request termination if their parent dies. A failed process cleanup stops the comparison. After workers close their descriptors, cleanup verifies the loop attachment's backing inode, detaches only that attachment, checks that the attachment is gone, and removes the owned sparse file.

## Artifacts and limits

`environment.json` records kernel, runner, dependency, header, hook, source-control, and installed-binary evidence. `events.jsonl` records RPC status, worker identity, syscall result, errno, byte count, BIO statistics, and cleanup as each assertion runs. `summary.json` reports the probability profiles, explicit invalid-update rejection, known-defect reproduction, functional pass, successful injection and update RPCs, observed faults, unaffected controls, same-process recoveries, and cleanup separately. Its top-level `passed` is true only when all three source-control cases reproduce the exact defect, all three candidate cases pass every assertion, and disk cleanup succeeds. A source-control case never has `passed=true` or `functional_pass=true`. Service logs remain separate for every case. The workflow uploads evidence even when qualification or an assertion fails.

Before guest boot, a separate read-only, unprivileged container records the producer image identity, service/driver/resource and resolved-library hashes, package versions, and compiler/linker text in `userland-image.json` and `userland-identity.json`. It has no network, a 30-second limit plus five-second termination grace, one CPU, 256 MiB memory and a 32-process limit. `ftrace-mode.json` is written only after the full guest run and the owned FTRACE checks pass. These files describe the current userland; they do not establish byte identity with earlier runs that lack corresponding hashes. Compare available source, binary, package and resolved-kernel evidence before attributing a configuration contrast to one cause.

A passing build or no-fault RPC check does not establish BPF loading, fault injection, or recovery. A failed capability probe leaves all runtime behavior unverified. A source-control result outside the exact known defect remains a runtime blocker, as does any candidate failure. Kubernetes `KernelChaos` integration and native arm64 fault injection are separate gates.
