# Kernel test evidence

The `Kernel fault qualification` workflow runs on a fresh `ubuntu-24.04` GitHub-hosted VM. Runtime qualification starts with native amd64. The separate build workflow checks native amd64 and arm64 without loading BPF programs.

The runtime workflow compares the candidate with runtime source from `2825d3832c9230ab6e26e8a47ed6de8d16ea5ae3`. Both use the same installed dependencies and current CMake build files. The artifact records the build shim and hashes every original runtime source file. This is a source control, not a historical known-good binary.

## Execution boundary

`tests/kernel/run.sh` accepts two installation prefixes and the built private driver. It creates its evidence directory under `/home/runner/work/_temp`. Both the launcher and driver require the GitHub-hosted Linux environment. There is no local or self-hosted override. The environment checks prevent accidental misuse and do not authenticate the host.

The capability probe reads the running kernel configuration, matching headers, hook symbols, and `/sys/kernel/debug/error_injection/list`. It requires the allowed return types for `should_failslab`, `should_fail_alloc_page`, and `should_fail_bio`. It also verifies the BIO device fields and that the loop driver is already loaded. Missing capabilities produce an `unsupported` result and a failing job. The probe does not load BPF, mount debugfs, change fault controls, or load kernel modules.

The driver owns the service and both persistent workers. Workers drop root privileges, clear supplementary groups, and set `no_new_privs` before execution. Pidfds bind supervision to the owned processes. PID and `/proc` start time are checked before operations and RPCs. Results use preallocated shared memory, so fault injection does not need a successful allocation to report its result.

## Assertions

Each fault case records successful operations before injection, then runs two injection and recovery cycles. The same target and control processes remain alive throughout the case.

1. Both workers complete an operation before injection.
2. The generated gRPC client injects into the target PID and checks transport status and `response.ret`.
3. The target reports the expected error. The control completes its operation.
4. The target reports the expected error again immediately before recovery.
5. Recovery sends the exact injection request. The same target process and the control complete their operations.
6. The second injection and recovery cycle repeats these assertions.

The injection request uses one direct-hook predicate frame, probability `1.0`, and unlimited count. Operation counts and deadlines bound the experiment. The pre-recovery assertion rejects counter exhaustion as evidence of recovery. The tests do not adjust frame counts to bypass the existing `fk_filter` layout concern. A map update failure or an unexpected successful operation fails the case.

The fixed worker operations are bounded.

| Fault | Target and control operation | Required error |
| --- | --- | --- |
| SLAB | Open and close `/dev/null`. | `ENOMEM` |
| PAGE | Write 4 KiB to a fresh nonblocking pipe. Pipe descriptors and the user buffer exist before injection. | `ENOMEM` |
| BIO | Read 4 KiB with `O_DIRECT` from the dedicated read-only loop disk. | `EIO` |

The BIO file is an 8 MiB sparse file owned by the driver. The driver attaches it read-only, validates its inode and loop device identity, and builds the predicate from the real device major and minor numbers. The predicate uses `bio->bi_bdev->bd_dev`. Successful BIO operations must also advance the loop device's read completion count. The tests do not mount filesystems or write block devices.

## Deadlines and cleanup

RPCs have 10-second deadlines. Worker readiness and operations have 3-second deadlines. Each case has a separate 75-second watchdog, and the comparison has an 8-minute deadline. The launcher adds a 540-second outer timeout with a 20-second termination grace period. The job timeout also bounds setup and compilation.

On a case failure, the driver kills and reaps its service first to detach probes, then stops both workers and the watchdog. The watchdog uses pidfds to enforce the same order on timeout or parent death. Service and worker processes also request termination if their parent dies. A failed process cleanup stops the comparison. After workers close their descriptors, cleanup verifies the loop attachment's backing inode, detaches only that attachment, checks that the attachment is gone, and removes the owned sparse file.

## Artifacts and limits

`environment.json` records kernel, runner, dependency, header, hook, source-control, and installed-binary evidence. `events.jsonl` records RPC status, worker identity, syscall result, errno, byte count, BIO statistics, and cleanup as each assertion runs. `summary.json` reports communication, successful BPF load and map-update RPCs, observed faults, unaffected controls, same-process recoveries, and cleanup for each case. Service logs remain separate for every case. The workflow uploads evidence even when qualification or an assertion fails.

A passing build or no-fault RPC check does not establish BPF loading, fault injection, or recovery. A failed capability probe leaves all runtime behavior unverified. A failure in both installations remains a runtime blocker. Kubernetes `KernelChaos` integration and native arm64 fault injection are separate gates.
