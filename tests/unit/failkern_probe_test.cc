#include "service.h"

#include <algorithm>
#include <cerrno>
#include <iostream>
#include <sstream>
#include <sys/random.h>

#include <bcc/libbpf.h>
#include <spdlog/sinks/ostream_sink.h>

namespace {

void Check(bool condition, const std::string& message) {
  if (!condition)
    throw std::runtime_error(message);
}

struct Attempt {
  std::string name;
  std::string symbol;
  bpf_probe_attach_type type;
  int program_fd;
  int perf_fd = -1;
};

struct SimulatedKernel {
  int next_program_fd = 20000;
  int next_perf_fd = 30000;
  int next_map_fd = 40000;
  size_t loads = 0;
  size_t writes = 0;
  size_t captures = 0;
  size_t rechecks = 0;
  size_t fail_load = 0;
  size_t fail_attach = 0;
  bool tracefs_path = true;
  bool capture_failure = false;
  bool recheck_failure = false;
  bool update_failure = false;
  bool entropy_failure = false;
  bool entropy_empty = false;
  bool entropy_interrupt = false;
  size_t entropy_chunk = 16;
  int close_error_fd = -1;
  std::string detach_error_name;
  bool boundary_error = false;
  std::map<int, std::string> programs;
  std::set<int> map_fds;
  std::vector<Attempt> attempts;
  std::set<std::string> used_names;
  std::map<int, std::string> live_perf;
  std::set<std::string> tracefs;
  std::vector<int> closed;
  std::vector<std::string> detached;
};

SimulatedKernel kernel;
uint64_t entropy_sequence = 0;

std::set<int> PerfFds() {
  std::set<int> fds;
  for (const auto& entry : kernel.live_perf)
    fds.insert(entry.first);
  return fds;
}

void Reset() {
  Check(kernel.live_perf.empty() && kernel.tracefs.empty(), "previous case left simulated attachments");
  kernel = SimulatedKernel{};
}

void CheckEmpty() {
  Check(kernel.live_perf.empty() && kernel.tracefs.empty(), "attachment cleanup is incomplete");
  Check(!kernel.boundary_error, "cleanup touched an unowned or still-open attachment");
}

}

extern "C" ssize_t __wrap_getrandom(void* output, size_t length, unsigned int flags) {
  Check(flags == 0, "unexpected entropy flags");
  if (kernel.entropy_failure || kernel.entropy_interrupt) {
    errno = kernel.entropy_failure ? EIO : EINTR;
    kernel.entropy_interrupt = false;
    return -1;
  }
  if (kernel.entropy_empty)
    return 0;
  const size_t count = std::min(length, kernel.entropy_chunk);
  const auto sequence = ++entropy_sequence;
  auto bytes = static_cast<unsigned char*>(output);
  for (size_t i = 0; i < count; ++i)
    bytes[i] = static_cast<unsigned char>(sequence >> ((i % 8) * 8));
  return static_cast<ssize_t>(count);
}

namespace ebpf {

StatusTuple BPF::load_func(const std::string& name, enum bpf_prog_type type,
                           int& fd, unsigned flags, enum bpf_attach_type attach_type) {
  Check(type == BPF_PROG_TYPE_KPROBE && flags == 0 && static_cast<int>(attach_type) == -1,
        "changed program load options");
  ++kernel.loads;
  if (kernel.loads == kernel.fail_load)
    return StatusTuple(-1, "simulated program load failure");
  fd = kernel.next_program_fd++;
  kernel.programs.emplace(fd, name);
  return StatusTuple::OK();
}

}

extern "C" int bpf_attach_kprobe(int program_fd, enum bpf_probe_attach_type type,
                                  const char* event_name, const char* symbol,
                                  uint64_t offset, int maxactive) {
  const std::string name(event_name);
  Check(name.size() >= 40 && name.size() <= 60 && name.compare(0, 6, "bpfki_") == 0 &&
        name[38] == '_' &&
        std::all_of(name.begin() + 6, name.begin() + 38, [](char c) {
          return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        }), "invalid or unbounded probe namespace");
  Check(kernel.used_names.insert(name).second, "probe event name was reused");
  Check(offset == 0 && maxactive == 0, "changed BCC attachment options");
  Check(kernel.programs.at(program_fd) == std::string(symbol) +
        (type == BPF_PROBE_ENTRY ? "_entry" : "_exit"), "attached the wrong program");
  kernel.attempts.push_back({name, symbol, type, program_fd});
  if (kernel.tracefs_path)
    kernel.tracefs.insert(name);
  if (kernel.attempts.size() == kernel.fail_attach) {
    errno = EIO;
    return -1;
  }
  const int fd = kernel.next_perf_fd++;
  kernel.attempts.back().perf_fd = fd;
  kernel.live_perf.emplace(fd, name);
  return fd;
}

extern "C" int bpf_close_perf_event_fd(int fd) {
  kernel.closed.push_back(fd);
  if (kernel.live_perf.erase(fd) != 1)
    kernel.boundary_error = true;
  if (fd == kernel.close_error_fd) {
    errno = EIO;
    return -1;
  }
  return 0;
}

extern "C" int bpf_detach_kprobe(const char* event_name) {
  const std::string name(event_name);
  if (kernel.used_names.count(name) != 1 ||
      std::find(kernel.detached.begin(), kernel.detached.end(), name) != kernel.detached.end() ||
      std::any_of(kernel.live_perf.begin(), kernel.live_perf.end(), [&name](const auto& entry) {
        return entry.second == name;
      }))
    kernel.boundary_error = true;
  kernel.detached.push_back(name);
  if (name == kernel.detach_error_name) {
    errno = EIO;
    return -1;
  }
  kernel.tracefs.erase(name);
  return 0;
}

extern "C" int bpf_update_elem(int fd, void*, void*, unsigned long long flags) {
  Check(kernel.map_fds.count(fd) == 1 && flags == BPF_ANY, "unexpected filter update");
  ++kernel.writes;
  if (kernel.update_failure) {
    errno = EIO;
    return -1;
  }
  return 0;
}

extern "C" int bpf_delete_elem(int fd, void*) {
  Check(kernel.map_fds.count(fd) == 1, "unexpected filter delete");
  return 0;
}

namespace bpfki {
namespace bio_probe {

std::set<int> SelfPerfFds() {
  return PerfFds();
}

Identity Capture(const std::set<int>& before, int program_fd, int map_fd) {
  ++kernel.captures;
  const auto& attempt = kernel.attempts.back();
  Check(attempt.symbol == "should_fail_bio" && attempt.type == BPF_PROBE_ENTRY &&
        attempt.program_fd == program_fd && before.count(attempt.perf_fd) == 0 &&
        kernel.live_perf.count(attempt.perf_fd) == 1 && kernel.map_fds.count(map_fd) == 1,
        "BIO capture lost the owned attachment");
  if (kernel.capture_failure)
    throw UnsupportedInjection("simulated BIO capture rejection");
  return {attempt.perf_fd, program_fd, static_cast<uint32_t>(program_fd),
          static_cast<uint32_t>(map_fd), 0xffffffff81001004};
}

void Recheck(const Identity& identity, int map_fd) {
  ++kernel.rechecks;
  Check(kernel.live_perf.count(identity.borrowed_perf_fd) == 1 &&
        identity.map_id == static_cast<uint32_t>(map_fd), "BIO recheck lost its owner");
  if (kernel.recheck_failure)
    throw UnsupportedInjection("simulated BIO recheck rejection");
}

}

struct FailKernTestAccess {
  static int InitWithoutLoading(FailKern& injection) {
    const auto program = injection.gen_bpf_prog();
    const int map_fd = kernel.next_map_fd++;
    kernel.map_fds.insert(map_fd);
    injection.filter_map_ = {map_fd, program.stack_slots};
    injection.attach_probes();
    return 0;
  }

  static void Configure(BPFKIServiceImpl& service);

  static const std::string& Boot(const BPFKIServiceImpl& service) {
    return service.kernel_session_.boot_id();
  }

  static bool Active(const BPFKIServiceImpl& service, const KernelFaultReference& reference) {
    return service.kernel_faults_.at(reference.handle().id()).active != nullptr;
  }

  static void PublishLegacy(BPFKIServiceImpl& service, const std::vector<FailKern::Frame>& frames,
                            std::unique_ptr<FailKern> injection) {
    const auto key = std::to_string(absl::Hash<std::vector<FailKern::Frame>>{}(frames));
    Check(service.bpfki_map_.emplace(key, std::move(injection)).second,
          "legacy injection was already present");
  }
};

class MockLoadedFailKern final : public FailKern {
 public:
  using FailKern::FailKern;
  int init() override {
    return FailKernTestAccess::InitWithoutLoading(*this);
  }
};

void FailKernTestAccess::Configure(BPFKIServiceImpl& service) {
  Check(service.kernel_session_status_.ok(), service.kernel_session_status_.error_message());
  service.read_process_start_ = [&service](uint32_t pid, uint64_t pid_namespace,
                                          std::optional<uint64_t>* start_time) {
    Check(pid == 4242 && pid_namespace == service.kernel_session_.pid_namespace(),
          "unexpected target process observation");
    *start_time = 123456;
    return grpc::Status::OK;
  };
  service.kernel_factory_ = [&service](FailKern::Type type, std::vector<std::string>& headers,
                                      std::vector<FailKern::Frame>& frames) {
    return std::make_unique<MockLoadedFailKern>(service.logger_, type, headers, frames);
  };
}

}

namespace {

struct Fixture {
  std::ostringstream messages;
  std::shared_ptr<spdlog::logger> logger = std::make_shared<spdlog::logger>(
      "probe-test", std::make_shared<spdlog::sinks::ostream_sink_mt>(messages));
  std::vector<std::string> legacy_headers;
  std::vector<bpfki::FailKern::Frame> legacy_frames;
  bpfki::BPFKIServiceImpl service{logger};
  bpfki::ReserveKernelFaultRequest request;

  explicit Fixture(bpfki::FailKern::Type type = bpfki::FailKern::PAGE) {
    bpfki::FailKernTestAccess::Configure(service);
    request.set_node_boot_id(bpfki::FailKernTestAccess::Boot(service));
    auto fault = request.mutable_fault();
    fault->set_pid(4242);
    fault->set_ftype(static_cast<bpfki::FailKernRequest::FAILTYPE>(type));
    fault->set_probability(1);
    fault->add_callchain()->set_funcname("vfs_read");
    fault->add_callchain()->set_funcname("read_iter");
  }

  bpfki::KernelFaultReference Reserve() {
    bpfki::KernelFaultReference reference;
    reference.set_node_boot_id(request.node_boot_id());
    Check(service.ReserveKernelFault(nullptr, &request, reference.mutable_handle()).ok(),
          "Reserve failed");
    return reference;
  }

  grpc::Status Arm(const bpfki::KernelFaultReference& reference) {
    bpfki::StatusResponse response;
    return service.ArmKernelFault(nullptr, &reference, &response);
  }

  void Release(const bpfki::KernelFaultReference& reference) {
    bpfki::ReleaseKernelFaultResponse response;
    Check(service.ReleaseKernelFault(nullptr, &reference, &response).ok() &&
          response.outcome() == bpfki::ReleaseKernelFaultResponse::RELEASED, "Release failed");
  }

  void AddLegacy() {
    for (const auto& frame : request.fault().callchain())
      legacy_frames.emplace_back(frame.funcname(), frame.parameters(), frame.predicate());
    auto injection = std::make_unique<bpfki::MockLoadedFailKern>(
        logger, static_cast<bpfki::FailKern::Type>(request.fault().ftype()), legacy_headers, legacy_frames);
    Check(injection->init() == 0 && injection->update_inject_cond(&request.fault()) == 1,
          "legacy initialization failed");
    bpfki::FailKernTestAccess::PublishLegacy(service, legacy_frames, std::move(injection));
  }
};

void Isolation(bool legacy, bool second_uses_tracefs) {
  Reset();
  Fixture test;
  bpfki::KernelFaultReference first;
  if (legacy) {
    test.AddLegacy();
  } else {
    first = test.Reserve();
    Check(test.Arm(first).ok(), "first Arm failed");
  }
  const auto first_perf = kernel.live_perf;
  const auto first_tracefs = kernel.tracefs;
  Check(first_perf.size() == 5, "callchain did not attach five probes");
  kernel.tracefs_path = second_uses_tracefs;
  const auto second = test.Reserve();
  Check(test.Arm(second).ok(), "second Arm failed");
  Check(kernel.attempts.size() == 10 && kernel.used_names.size() == 10,
        "same-symbol owners did not use distinct event names");
  for (size_t i = 0; i < 5; ++i)
    Check(kernel.attempts[i].symbol == kernel.attempts[i + 5].symbol &&
          kernel.attempts[i].type == kernel.attempts[i + 5].type, "owners used different probes");
  const auto writes = kernel.writes;
  Check(test.Arm(second).ok() && kernel.attempts.size() == 10 && kernel.writes == writes,
        "duplicate Arm recreated attachments or reset the filter");
  test.Release(second);
  Check(kernel.live_perf == first_perf && kernel.tracefs == first_tracefs &&
        kernel.closed.size() == 5 && kernel.detached.size() == 5,
        "Release changed the other owner's attachments");
  bpfki::StatusResponse response;
  if (legacy) {
    Check(test.service.FailMMOrBIO(nullptr, &test.request.fault(), &response).ok(),
          "legacy owner was unusable after private Release");
    Check(test.service.RecoverMMOrBIO(nullptr, &test.request.fault(), &response).ok(),
          "legacy recovery failed");
  } else {
    Check(test.Arm(first).ok() && kernel.live_perf == first_perf,
          "remaining handle lost its active attachment");
    test.Release(first);
  }
  CheckEmpty();
}

void LoadAndAttachFailures() {
  for (bool load_failure : {true, false}) {
    for (size_t fail_at : {1, 4}) {
      Reset();
      Fixture test;
      const auto reference = test.Reserve();
      kernel.fail_load = load_failure ? fail_at : 0;
      kernel.fail_attach = load_failure ? 0 : fail_at;
      Check(test.Arm(reference).error_code() == grpc::StatusCode::INTERNAL,
            "failed load or attachment was accepted");
      Check(!bpfki::FailKernTestAccess::Active(test.service, reference),
            "failed attachment was published active");
      Check(kernel.closed.size() == fail_at - 1 &&
            kernel.detached.size() == (load_failure ? fail_at - 1 : fail_at),
            "failed attempt was detached incorrectly or an invalid FD was closed");
      CheckEmpty();
      const auto previous_names = kernel.used_names;
      kernel.fail_load = kernel.fail_attach = 0;
      Check(test.Arm(reference).ok(), "Arm retry failed");
      Check(kernel.used_names.size() == previous_names.size() + 5,
            "Arm retry reused a failed object's namespace");
      test.Release(reference);
      CheckEmpty();
    }
  }
}

void BioAndFilterFailures() {
  enum class Failure { Capture, Recheck, Update };
  for (auto failure : {Failure::Capture, Failure::Recheck, Failure::Update}) {
    Reset();
    Fixture test(bpfki::FailKern::BIO);
    const auto reference = test.Reserve();
    kernel.capture_failure = failure == Failure::Capture;
    kernel.recheck_failure = failure == Failure::Recheck;
    kernel.update_failure = failure == Failure::Update;
    const auto code = failure == Failure::Update ? grpc::StatusCode::INTERNAL
                                                : grpc::StatusCode::FAILED_PRECONDITION;
    Check(test.Arm(reference).error_code() == code, "BIO or filter failure was accepted");
    const size_t count = failure == Failure::Capture ? 1 : 5;
    Check(kernel.captures == 1 && kernel.rechecks == (failure == Failure::Capture ? 0 : 1) &&
          kernel.attempts.size() == count && kernel.closed.size() == count &&
          kernel.detached.size() == count &&
          !bpfki::FailKernTestAccess::Active(test.service, reference),
          "BIO or filter rejection did not unwind all attachments");
    CheckEmpty();
  }
}

void EntropyFailures() {
  for (bool empty : {false, true}) {
    Reset();
    Fixture test;
    const auto reference = test.Reserve();
    kernel.entropy_failure = !empty;
    kernel.entropy_empty = empty;
    Check(test.Arm(reference).error_code() == grpc::StatusCode::INTERNAL &&
          kernel.loads == 0 && kernel.attempts.empty() && kernel.detached.empty(),
          "entropy failure did not fail before program loads and attachments");
    kernel.entropy_failure = kernel.entropy_empty = false;
    kernel.entropy_interrupt = true;
    kernel.entropy_chunk = 5;
    Check(test.Arm(reference).ok(), "interrupted or partial entropy read failed");
    test.Release(reference);
    CheckEmpty();
  }
}

void CleanupErrors() {
  Reset();
  Fixture test;
  const auto reference = test.Reserve();
  Check(test.Arm(reference).ok(), "Arm failed before cleanup error case");
  kernel.close_error_fd = kernel.attempts[0].perf_fd;
  kernel.detach_error_name = kernel.attempts[1].name;
  test.Release(reference);
  Check(kernel.live_perf.empty() && kernel.closed.size() == 5 && kernel.detached.size() == 5 &&
        kernel.tracefs == std::set<std::string>{kernel.detach_error_name} && !kernel.boundary_error,
        "cleanup error prevented later cleanup or hid the remaining tracefs event");
  Check(test.messages.str().find("perf FD close failed") != std::string::npos &&
        test.messages.str().find("tracefs event removal failed") != std::string::npos &&
        test.messages.str().find(kernel.detach_error_name) != std::string::npos,
        "cleanup failure was not logged");
  kernel.tracefs.clear();
}

}

int main() {
  try {
    Isolation(false, true);
    Isolation(true, false);
    LoadAndAttachFailures();
    BioAndFilterFailures();
    EntropyFailures();
    CleanupErrors();
    std::cout << "PASS: actual FailKern attachment ownership and RPC cleanup with simulated BCC calls.\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
