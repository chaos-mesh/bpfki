#include "service.h"

#include <algorithm>
#include <limits>
#include <spdlog/sinks/null_sink.h>

namespace {

void Check(bool condition, const std::string& message) {
  if (!condition)
    throw std::runtime_error(message);
}

grpc::Status ReadTestSession(bpfki::KernelFaultSession* session) {
  session->set_boot_id("00000000-0000-0000-0000-000000000001");
  session->set_instance("11111111111111111111111111111111");
  session->set_pid(1234);
  session->set_start_time(1000);
  session->set_pid_namespace(4026531836);
  return grpc::Status::OK;
}

struct Object {
  int init_calls = 0;
  int writes = 0;
  int clears = 0;
  bool active = false;
  bool destroyed = false;
  size_t initial_frames = 0;
  std::vector<std::string> headers_at_destruction;
  bpfki::FailKernRequest request;
};

enum class Failure { None, Init, Unsupported, Update, InitResult, UpdateResult };

struct ProcessObservation {
  grpc::Status status;
  std::optional<uint64_t> start_time;
  int reads = 0;
  uint64_t pid_namespace = 0;
};

struct Observations {
  Failure failure = Failure::None;
  std::vector<std::shared_ptr<Object>> objects;
  std::map<uint32_t, ProcessObservation> processes;
  std::function<void()> on_init;
};

class FakeInjection final : public bpfki::BPFKI {
 public:
  FakeInjection(Observations& observations, std::vector<std::string>& headers,
                std::vector<bpfki::FailKern::Frame>& frames)
      : observations_(observations), headers_(headers), frames_(frames),
        object_(std::make_shared<Object>()) {
    object_->initial_frames = frames.size();
    observations_.objects.push_back(object_);
  }

  int init() override {
    ++object_->init_calls;
    if (!frames_.empty() && frames_.back().funcname().empty())
      frames_.pop_back();
    if (observations_.failure == Failure::Init)
      throw std::invalid_argument("simulated initialization failure");
    if (observations_.failure == Failure::Unsupported)
      throw bpfki::UnsupportedInjection("simulated unsupported BIO attachment");
    if (observations_.on_init)
      observations_.on_init();
    return observations_.failure == Failure::InitResult ? -1 : 0;
  }

  int update_inject_cond(const void* request, bool clear) override {
    if (clear) {
      ++object_->clears;
      object_->active = false;
      return 0;
    }
    ++object_->writes;
    object_->request = *static_cast<const bpfki::FailKernRequest*>(request);
    object_->active = true;
    if (observations_.failure == Failure::Update)
      throw std::invalid_argument("simulated failure after partial filter write");
    return observations_.failure == Failure::UpdateResult ? -1 : 1;
  }

  ~FakeInjection() override {
    object_->headers_at_destruction = headers_;
    object_->active = false;
    object_->destroyed = true;
  }

 private:
  Observations& observations_;
  std::vector<std::string>& headers_;
  std::vector<bpfki::FailKern::Frame>& frames_;
  std::shared_ptr<Object> object_;
};

}

namespace bpfki {

struct KernelFaultTestAccess {
  static BPFKIServiceImpl Create(const std::shared_ptr<spdlog::logger>& logger,
                                 grpc::Status (*read_session)(KernelFaultSession*)) {
    return BPFKIServiceImpl(logger, read_session);
  }

  static void Configure(BPFKIServiceImpl& service, Observations& observations,
                        std::chrono::steady_clock::time_point& now) {
    service.now_ = [&now] { return now; };
    service.kernel_factory_ = [&observations](FailKern::Type, std::vector<std::string>& headers,
                                             std::vector<FailKern::Frame>& frames) {
      return std::make_unique<FakeInjection>(observations, headers, frames);
    };
    service.read_process_start_ = [&observations](uint32_t pid, uint64_t pid_namespace,
                                                std::optional<uint64_t>* start_time) {
      auto& process = observations.processes[pid];
      ++process.reads;
      process.pid_namespace = pid_namespace;
      *start_time = process.start_time;
      return process.status;
    };
  }

  static const KernelFaultSession& Session(const BPFKIServiceImpl& service) {
    return service.kernel_session_;
  }

  static void PublishLegacy(BPFKIServiceImpl& service, const FailKernRequest& request,
                            std::unique_ptr<BPFKI> injection) {
    std::vector<FailKern::Frame> frames;
    for (const auto& frame : request.callchain())
      frames.emplace_back(frame.funcname(), frame.parameters(), frame.predicate());
    const auto key = std::to_string(absl::Hash<std::vector<FailKern::Frame>>{}(frames));
    service.bpfki_map_.emplace(key, std::move(injection));
  }

  static grpc::Status ParseStat(const std::string& stat, uint32_t pid, uint64_t* ticks) {
    return BPFKIServiceImpl::ParseProcessStart(stat, pid, ticks);
  }
};

}

namespace {

using Code = grpc::StatusCode;
using Outcome = bpfki::ReleaseKernelFaultResponse;

struct Fixture {
  Observations observations;
  std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
  std::shared_ptr<spdlog::logger> logger = std::make_shared<spdlog::logger>(
      "kernel-fault-test", std::make_shared<spdlog::sinks::null_sink_mt>());
  std::vector<std::string> legacy_headers{"linux/sched.h"};
  std::vector<bpfki::FailKern::Frame> legacy_frames;
  bpfki::BPFKIServiceImpl service;
  bpfki::ReserveKernelFaultRequest request;

  explicit Fixture(grpc::Status (*read_session)(bpfki::KernelFaultSession*) = ReadTestSession)
      : service(bpfki::KernelFaultTestAccess::Create(logger, read_session)) {
    bpfki::KernelFaultTestAccess::Configure(service, observations, now);
    request.set_node_boot_id("00000000-0000-0000-0000-000000000001");
    auto fault = request.mutable_fault();
    fault->set_pid(4242);
    observations.processes[4242].start_time = 100;
    fault->set_ftype(bpfki::FailKernRequest::PAGE);
    fault->set_probability(0.25);
    fault->set_times(7);
    fault->add_headers("linux/sched.h");
    fault->add_callchain()->set_funcname("vfs_read");
    fault->add_callchain()->set_predicate("1");
  }

  bpfki::KernelFaultReference Reserve() {
    bpfki::KernelFaultReference reference;
    reference.set_node_boot_id(request.node_boot_id());
    const auto status = service.ReserveKernelFault(nullptr, &request, reference.mutable_handle());
    Check(status.ok(), "Reserve failed: " + status.error_message());
    const auto& id = reference.handle().id();
    Check(id.size() == 32 && std::all_of(id.begin(), id.end(), [](char c) {
      return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    }), "Reserve omitted the random handle");
    const auto& session = reference.handle().session();
    Check(reference.handle().has_session() &&
          session.boot_id() == "00000000-0000-0000-0000-000000000001" &&
          session.instance() == "11111111111111111111111111111111" && session.pid() == 1234 &&
          session.start_time() == 1000 && session.pid_namespace() == 4026531836,
          "Reserve did not return the complete simulated session");
    return reference;
  }

  grpc::Status Arm(const bpfki::KernelFaultReference& reference) {
    bpfki::StatusResponse response;
    const auto status = service.ArmKernelFault(nullptr, &reference, &response);
    if (status.ok())
      Check(response.ret() == 0 && response.msg().empty(), "Arm returned an error payload");
    return status;
  }

  grpc::Status Release(const bpfki::KernelFaultReference& reference, Outcome::Outcome expected) {
    bpfki::ReleaseKernelFaultResponse response;
    const auto status = service.ReleaseKernelFault(nullptr, &reference, &response);
    if (status.ok())
      Check(response.outcome() == expected, "Release returned an unexpected outcome");
    else
      Check(response.outcome() == Outcome::UNSPECIFIED, "failed Release claimed a cleanup outcome");
    return status;
  }
};

void StartupFailures() {
  struct FailureCase {
    grpc::Status (*read_session)(bpfki::KernelFaultSession*);
    Code code;
    const char* message;
  };
  const FailureCase failures[]{
      {[](bpfki::KernelFaultSession*) -> grpc::Status {
         return {Code::UNAVAILABLE, "simulated unreadable session metadata"};
       }, Code::UNAVAILABLE, "simulated unreadable session metadata"},
      {[](bpfki::KernelFaultSession*) -> grpc::Status {
         return {Code::FAILED_PRECONDITION, "simulated procfs namespace mismatch"};
       }, Code::FAILED_PRECONDITION, "simulated procfs namespace mismatch"},
  };
  for (const auto& failure : failures) {
    Fixture test(failure.read_session);
    bpfki::KernelFaultReference reference;
    reference.set_node_boot_id(test.request.node_boot_id());
    reference.mutable_handle()->set_id("22222222222222222222222222222222");
    ReadTestSession(reference.mutable_handle()->mutable_session());

    auto handle = reference.handle();
    const auto reserve = test.service.ReserveKernelFault(nullptr, &test.request, &handle);
    Check(reserve.error_code() == failure.code && reserve.error_message() == failure.message &&
          handle.id().empty() && !handle.has_session(),
          "Reserve did not propagate the startup failure and clear its response");

    bpfki::StatusResponse arm_response;
    arm_response.set_ret(-1);
    arm_response.set_msg("previous response");
    const auto arm = test.service.ArmKernelFault(nullptr, &reference, &arm_response);
    Check(arm.error_code() == failure.code && arm.error_message() == failure.message &&
          arm_response.ret() == 0 && arm_response.msg().empty(),
          "Arm did not propagate the startup failure and clear its response");

    bpfki::ReleaseKernelFaultResponse release_response;
    release_response.set_outcome(Outcome::SERVICE_GONE);
    const auto release = test.service.ReleaseKernelFault(nullptr, &reference, &release_response);
    Check(release.error_code() == failure.code && release.error_message() == failure.message &&
          release_response.outcome() == Outcome::UNSPECIFIED,
          "Release did not propagate the startup failure without a cleanup outcome");
    Check(test.observations.objects.empty(), "startup failure reached BPF construction");
    for (const auto& process : test.observations.processes)
      Check(process.second.reads == 0, "startup failure reached process observation");
  }
}

void OwnedLifecycle() {
  Fixture test;
  auto first = test.Reserve();
  test.request.mutable_fault()->set_ftype(bpfki::FailKernRequest::SLAB);
  auto second = test.Reserve();
  Check(first.handle().id() != second.handle().id(), "two reservations reused a handle");
  Check(test.observations.objects.empty(), "Reserve constructed a BPF object");
  test.request.mutable_fault()->set_pid(9000);
  test.request.mutable_fault()->set_probability(1);
  test.request.mutable_fault()->set_times(99);
  Check(test.Arm(first).ok() && test.Arm(second).ok(), "independent handles did not arm");
  Check(test.observations.objects.size() == 2, "same PID/callchain shared a BPF object");
  const auto first_object = test.observations.objects[0];
  const auto second_object = test.observations.objects[1];
  Check(first_object->request.pid() == 4242 && first_object->request.probability() == 0.25 &&
        first_object->request.times() == 7 && first_object->request.ftype() == bpfki::FailKernRequest::PAGE &&
        second_object->request.ftype() == bpfki::FailKernRequest::SLAB,
        "Arm did not use the immutable reserved request");
  auto& target = test.observations.processes[4242];
  const auto target_reads = target.reads;
  Check(test.Arm(first).ok() && first_object->init_calls == 1 && first_object->writes == 1,
        "duplicate Arm reset the active filter");
  test.now += std::chrono::hours(24);
  Check(test.Arm(first).ok() && first_object->active, "active reservation expired");
  target.start_time.reset();
  Check(test.Arm(first).ok() && first_object->writes == 1 && target.reads == target_reads,
        "duplicate active Arm depended on the dead target or reset its filter");
  Check(test.Release(first, Outcome::RELEASED).ok(), "owned Release depended on the target PID");
  Check(first_object->destroyed && !first_object->active && first_object->clears == 0 &&
        first_object->headers_at_destruction == std::vector<std::string>{"linux/sched.h"} &&
        second_object->active && !second_object->destroyed && target.reads == target_reads,
        "Release did not destroy only its own complete resource");
  Check(test.Release(first, Outcome::ABSENT).ok(), "repeated Release was not idempotent");
  Check(test.Arm(first).error_code() == Code::NOT_FOUND, "late Arm recreated a released handle");
  Check(test.Arm(second).ok() && second_object->writes == 1, "another owner's filter changed");
  Check(test.Release(second, Outcome::RELEASED).ok() && second_object->destroyed,
        "second owner's Release failed");
}

void ReserveRequiresPresentTarget() {
  for (const auto expected : {Code::NOT_FOUND, Code::UNAVAILABLE, Code::FAILED_PRECONDITION}) {
    Fixture test;
    auto& target = test.observations.processes[4242];
    target.start_time.reset();
    if (expected != Code::NOT_FOUND)
      target.status = {expected, "target process metadata cannot be trusted"};
    bpfki::KernelFaultHandle handle;
    handle.set_id("previous response");
    const auto status = test.service.ReserveKernelFault(nullptr, &test.request, &handle);
    Check(status.error_code() == expected && handle.id().empty() && !handle.has_session() &&
          test.observations.objects.empty(), "Reserve accepted a missing or unreadable target");
    Check(target.reads == 1 && target.pid_namespace ==
          bpfki::KernelFaultTestAccess::Session(test.service).pid_namespace(),
          "Reserve did not observe the target in the service PID namespace");
    target.status = grpc::Status::OK;
    target.start_time = 100;
    const auto valid = test.Reserve();
    Check(test.Release(valid, Outcome::RELEASED).ok(), "a later live target could not be reserved");
  }
}

void TargetChangesBeforeActivation() {
  struct Change {
    const char* name;
    std::optional<uint64_t> start_time;
    grpc::Status status;
    Code expected;
  };
  const std::vector<Change> changes{
      {"missing", std::nullopt, grpc::Status::OK, Code::NOT_FOUND},
      {"PID reused", 101, grpc::Status::OK, Code::NOT_FOUND},
      {"unreadable", std::nullopt, {Code::UNAVAILABLE, "unreadable proc metadata"}, Code::UNAVAILABLE},
      {"changed procfs namespace", std::nullopt,
       {Code::FAILED_PRECONDITION, "procfs namespace changed"}, Code::FAILED_PRECONDITION},
  };
  for (const auto& change : changes) {
    for (const bool during_init : {false, true}) {
      Fixture test;
      const auto reference = test.Reserve();
      auto& target = test.observations.processes[4242];
      const auto change_target = [&target, &change] {
        target.start_time = change.start_time;
        target.status = change.status;
      };
      if (during_init)
        test.observations.on_init = change_target;
      else
        change_target();
      Check(test.Arm(reference).error_code() == change.expected,
            std::string("Arm accepted a target that became ") + change.name);
      Check(test.observations.objects.size() == (during_init ? 1U : 0U),
            "Arm constructed BPF before validating the reserved target");
      if (during_init) {
        const auto object = test.observations.objects[0];
        Check(object->init_calls == 1 && object->writes == 0 && object->destroyed && !object->active,
              "target change during initialization published or retained a fault");
      }
      const auto target_reads = target.reads;
      Check(test.Release(reference, Outcome::RELEASED).ok() && target.reads == target_reads,
            "rejected Arm could not release its reservation without target metadata");
      Check(test.Arm(reference).error_code() == Code::NOT_FOUND,
            "late Arm recreated a released target reservation");
    }
  }
}

void UnarmedReservations() {
  Fixture test;
  auto released = test.Reserve();
  Check(test.Release(released, Outcome::RELEASED).ok(), "unarmed Release failed");
  Check(test.Arm(released).error_code() == Code::NOT_FOUND, "released unarmed handle was recreated");
  auto expired = test.Reserve();
  test.now += std::chrono::minutes(6);
  Check(test.Arm(expired).error_code() == Code::NOT_FOUND, "expired handle was armed");
  Check(test.Release(expired, Outcome::ABSENT).ok(), "expired handle was not absent");
  auto orphan = test.Reserve();
  test.now += std::chrono::minutes(6);
  auto later = test.Reserve();
  Check(test.Release(orphan, Outcome::ABSENT).ok(), "Reserve did not collect expired pending state");
  Check(test.Release(later, Outcome::RELEASED).ok(), "fresh reservation was collected");
  Check(test.observations.objects.empty(), "unarmed lifecycle reached the BPF factory");

  for (size_t i = 0; i < 1024; ++i)
    test.Reserve();
  bpfki::KernelFaultHandle handle;
  Check(test.service.ReserveKernelFault(nullptr, &test.request, &handle).error_code() == Code::RESOURCE_EXHAUSTED,
        "pending reservations were not bounded");
  test.now += std::chrono::minutes(6);
  auto after_limit = test.Reserve();
  Check(test.Release(after_limit, Outcome::RELEASED).ok() && test.observations.objects.empty(),
        "expired pending limit did not recover without BPF construction");
}

void PartialArmFailures() {
  for (const auto failure : {Failure::Init, Failure::Unsupported, Failure::Update,
                            Failure::InitResult, Failure::UpdateResult}) {
    Fixture test;
    const auto reference = test.Reserve();
    test.observations.failure = failure;
    const auto expected = failure == Failure::Unsupported ? Code::FAILED_PRECONDITION : Code::INTERNAL;
    Check(test.Arm(reference).error_code() == expected, "partial Arm returned the wrong failure");
    Check(test.observations.objects.size() == 1 && test.observations.objects[0]->destroyed &&
          !test.observations.objects[0]->active, "partial Arm retained a BPF resource");
    test.observations.failure = Failure::None;
    Check(test.Arm(reference).ok() && test.observations.objects.size() == 2 &&
          test.observations.objects[1]->initial_frames == 2 && test.observations.objects[1]->writes == 1,
          "retry did not rebuild the request vectors before initializing");
    Check(test.Release(reference, Outcome::RELEASED).ok() && test.observations.objects[1]->destroyed,
          "retried Arm was not releasable");
  }
  Fixture test;
  const auto reference = test.Reserve();
  test.observations.failure = Failure::Update;
  Check(test.Arm(reference).error_code() == Code::INTERNAL, "failed Arm unexpectedly succeeded");
  Check(test.Release(reference, Outcome::RELEASED).ok(), "failed Arm could not be cancelled");
  test.observations.failure = Failure::None;
  Check(test.Arm(reference).error_code() == Code::NOT_FOUND && test.observations.objects.size() == 1,
        "late retry recreated a cancelled failed Arm");
}

void LegacyIsolation() {
  Fixture test;
  const auto first = test.Reserve();
  const auto second = test.Reserve();
  auto legacy = std::make_unique<FakeInjection>(test.observations, test.legacy_headers, test.legacy_frames);
  bpfki::KernelFaultTestAccess::PublishLegacy(test.service, test.request.fault(), std::move(legacy));
  bpfki::StatusResponse response;
  Check(test.service.FailMMOrBIO(nullptr, &test.request.fault(), &response).ok(), "legacy cached set failed");
  Check(test.Arm(first).ok() && test.Arm(second).ok(), "owned handles did not coexist with legacy state");
  const auto legacy_object = test.observations.objects[0];
  const auto first_object = test.observations.objects[1];
  const auto second_object = test.observations.objects[2];
  Check(test.Release(first, Outcome::RELEASED).ok() && first_object->destroyed &&
        legacy_object->active && second_object->active, "owned Release changed legacy or another handle");
  Check(test.service.RecoverMMOrBIO(nullptr, &test.request.fault(), &response).ok() &&
        legacy_object->destroyed && legacy_object->clears == 1 && second_object->active,
        "legacy recovery changed an owned handle");
  Check(test.Arm(second).ok() && second_object->writes == 1, "legacy recovery reset an owned handle");
  Check(test.Release(second, Outcome::RELEASED).ok(), "final owned Release failed");
}

std::string DifferentBoot(const std::string& boot) {
  auto changed = boot;
  changed[0] = changed[0] == '0' ? '1' : '0';
  return changed;
}

bpfki::KernelFaultReference OtherInstance(bpfki::KernelFaultReference reference) {
  auto instance = reference.handle().session().instance();
  instance[0] = instance[0] == '0' ? '1' : '0';
  reference.mutable_handle()->mutable_session()->set_instance(instance);
  return reference;
}

void ServiceDeathWitness() {
  Fixture test;
  const auto current = test.Reserve();
  Check(test.Arm(current).ok(), "current handle failed to arm");
  auto old = OtherInstance(current);
  auto old_session = old.mutable_handle()->mutable_session();
  old_session->set_pid(7331);
  auto& old_process = test.observations.processes[old_session->pid()];
  old_process.start_time = old_session->start_time();
  const auto target_reads = test.observations.processes[4242].reads;
  Check(test.Arm(old).error_code() == Code::ABORTED, "old-session Arm did not fail");
  Check(test.Release(old, Outcome::UNSPECIFIED).error_code() == Code::FAILED_PRECONDITION,
        "a live old service was treated as gone");
  Check(old_process.reads == 1 && old_process.pid_namespace == old_session->pid_namespace() &&
        test.observations.processes[4242].reads == target_reads,
        "death proof used a different process identity");
  old_process.start_time.reset();
  Check(test.Release(old, Outcome::SERVICE_GONE).ok(), "absent old service was not proved gone");
  old_process.start_time = old_session->start_time() + 1;
  Check(test.Release(old, Outcome::SERVICE_GONE).ok(), "reused service PID was not distinguished");
  old_process.status = {Code::UNAVAILABLE, "unreadable or corrupt proc metadata"};
  Check(test.Release(old, Outcome::UNSPECIFIED).error_code() == Code::UNAVAILABLE,
        "unknown process metadata was treated as death");
  old_process.status = {Code::FAILED_PRECONDITION, "procfs namespace changed"};
  Check(test.Release(old, Outcome::UNSPECIFIED).error_code() == Code::FAILED_PRECONDITION,
        "changed procfs namespace was accepted");
  const auto reads = old_process.reads;
  old_session->set_pid_namespace(old_session->pid_namespace() + 1);
  Check(test.Release(old, Outcome::UNSPECIFIED).error_code() == Code::FAILED_PRECONDITION &&
        old_process.reads == reads, "foreign PID namespace reached numeric PID lookup");
  old_session->set_boot_id(DifferentBoot(current.node_boot_id()));
  Check(test.Release(old, Outcome::SERVICE_GONE).ok() && old_process.reads == reads,
        "verified node reboot did not prove the old service gone");
  old.set_node_boot_id(DifferentBoot(current.node_boot_id()));
  Check(test.Release(old, Outcome::UNSPECIFIED).error_code() == Code::FAILED_PRECONDITION &&
        old_process.reads == reads, "wrong-node boot ID was accepted as death proof");
  Check(test.Arm(current).ok() && test.observations.objects.size() == 1 &&
        test.observations.objects[0]->writes == 1 && test.observations.objects[0]->active,
        "foreign-session cleanup touched the current owner's resource");
  Check(test.Release(current, Outcome::RELEASED).ok(), "current owner's resource was lost");
}

void InvalidRequests() {
  Fixture test;
  const auto original = test.request;
  auto rejected = [&](Code code) {
    bpfki::KernelFaultHandle handle;
    const auto status = test.service.ReserveKernelFault(nullptr, &test.request, &handle);
    Check(status.error_code() == code && handle.id().empty() && test.observations.objects.empty(),
          "invalid Reserve was accepted or constructed BPF");
    test.request = original;
  };
  test.request.clear_fault();
  rejected(Code::INVALID_ARGUMENT);
  test.request.mutable_fault()->set_pid(0);
  rejected(Code::INVALID_ARGUMENT);
  test.request.mutable_fault()->set_tid(42);
  rejected(Code::INVALID_ARGUMENT);
  test.request.mutable_fault()->set_ftype(static_cast<bpfki::FailKernRequest::FAILTYPE>(99));
  rejected(Code::INVALID_ARGUMENT);
  for (const auto probability : {-0.1f, 1.1f, std::numeric_limits<float>::infinity(),
                                std::numeric_limits<float>::quiet_NaN()}) {
    test.request.mutable_fault()->set_probability(probability);
    rejected(Code::INVALID_ARGUMENT);
  }
  test.request.mutable_fault()->mutable_callchain(0)->clear_funcname();
  rejected(Code::INVALID_ARGUMENT);
  test.request.clear_node_boot_id();
  rejected(Code::INVALID_ARGUMENT);
  test.request.set_node_boot_id(DifferentBoot(original.node_boot_id()));
  rejected(Code::FAILED_PRECONDITION);

  const auto valid = test.Reserve();
  auto invalid = valid;
  invalid.mutable_handle()->clear_id();
  Check(test.Arm(invalid).error_code() == Code::INVALID_ARGUMENT &&
        test.Release(invalid, Outcome::UNSPECIFIED).error_code() == Code::INVALID_ARGUMENT,
        "empty handle was accepted");
  invalid = valid;
  invalid.mutable_handle()->mutable_session()->set_start_time(0);
  Check(test.Arm(invalid).error_code() == Code::INVALID_ARGUMENT &&
        test.Release(invalid, Outcome::UNSPECIFIED).error_code() == Code::INVALID_ARGUMENT,
        "incomplete witness was accepted");
  invalid = valid;
  invalid.mutable_handle()->mutable_session()->set_start_time(valid.handle().session().start_time() + 1);
  Check(test.Arm(invalid).error_code() == Code::FAILED_PRECONDITION &&
        test.Release(invalid, Outcome::UNSPECIFIED).error_code() == Code::FAILED_PRECONDITION,
        "inconsistent same-instance witness was accepted");
  invalid = valid;
  invalid.set_node_boot_id(DifferentBoot(valid.node_boot_id()));
  Check(test.Arm(invalid).error_code() == Code::FAILED_PRECONDITION &&
        test.Release(invalid, Outcome::UNSPECIFIED).error_code() == Code::FAILED_PRECONDITION,
        "wrong-node request mutated owned state");
  Check(test.observations.objects.empty(), "invalid Arm reached the BPF factory");
  Check(test.Release(valid, Outcome::RELEASED).ok(), "invalid requests removed the valid reservation");
}

std::string ProcessStat(uint32_t pid, const std::string& name, const std::string& ticks) {
  std::string stat = std::to_string(pid) + " (" + name + ") S";
  for (int field = 4; field <= 21; ++field)
    stat += field == 18 ? " -20" : " 0";
  return stat + " " + ticks + " 0 0\n";
}

void ProcessMetadata() {
  uint64_t ticks = 0;
  Check(bpfki::KernelFaultTestAccess::ParseStat(ProcessStat(42, "a name ) with ( parentheses\n", "123456"),
                                              42, &ticks).ok() && ticks == 123456,
        "process comm confused the start-time parser");
  for (const auto& malformed : {std::string(), std::string("42 (unfinished"),
                               ProcessStat(43, "wrong pid", "123456"),
                               ProcessStat(42, "negative", "-1"),
                               ProcessStat(42, "zero", "0"),
                               ProcessStat(42, "overflow", "18446744073709551616"),
                               ProcessStat(42, "trailing", "123x"),
                               std::string("42 (short) S 0 0 0")}) {
    Check(bpfki::KernelFaultTestAccess::ParseStat(malformed, 42, &ticks).error_code() == Code::UNAVAILABLE,
          "corrupt process stat was accepted");
  }
}

}

int main() {
  try {
    StartupFailures();
    OwnedLifecycle();
    TargetChangesBeforeActivation();
    ReserveRequiresPresentTarget();
    UnarmedReservations();
    PartialArmFailures();
    LegacyIsolation();
    ServiceDeathWitness();
    InvalidRequests();
    ProcessMetadata();
    std::cout << "PASS: actual owned lifecycle RPC branches with fake BPF construction, initialization, "
                 "filter writes, and destruction; target process lifetime checks, process witness "
                 "parsing, and fail-closed recovery.\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
