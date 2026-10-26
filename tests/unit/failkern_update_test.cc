#include "service.h"
#include "filter_layout.h"

#include <cerrno>
#include <iostream>
#include <spdlog/sinks/null_sink.h>

namespace {

const bpfki::bio_probe::Identity identity{902, 903, 17, 23, 0xffffffff81001004};
bpfki::bio_probe::Query query{17, true, "should_fail_bio", 0, identity.address};
bpfki::bio_probe::Program program{17, {23}};
uint32_t map_id = 23;
const std::string ftrace = "ffffffff81001004 k should_fail_bio+0x4 [FTRACE]\n";
std::string listing = ftrace;
bool query_failure = false;
bool write_failure = false;
size_t checks = 0, writes = 0, deletes = 0;
std::map<uint32_t, std::vector<uint64_t>> filters;

void Check(bool condition, const std::string& message) {
  if (!condition)
    throw std::runtime_error(message);
}

}

extern "C" int bpf_update_elem(int fd, void* key, void* value, unsigned long long) {
  Check(fd == 901, "unexpected update FD");
  ++writes;
  if (write_failure) {
    errno = EIO;
    return -1;
  }
  const auto words = static_cast<const uint64_t*>(value);
  filters[*static_cast<uint32_t*>(key)] =
      std::vector<uint64_t>(words, words + bpfki::filter_layout::field_count + 1);
  return 0;
}

extern "C" int bpf_delete_elem(int fd, void* key) {
  Check(fd == 901, "unexpected delete FD");
  ++deletes;
  return filters.erase(*static_cast<uint32_t*>(key)) == 1 ? 0 : -1;
}

namespace bpfki {
namespace bio_probe {

std::set<int> SelfPerfFds() {
  throw std::runtime_error("no-fault update test must not attach probes");
}

Identity Capture(const std::set<int>&, int, int) {
  throw std::runtime_error("no-fault update test must not capture attachments");
}

void Recheck(const Identity& owned, int fd) {
  Check(fd == 901, "unexpected metadata map FD");
  ++checks;
  if (query_failure)
    throw UnsupportedInjection("BIO unsupported: perf FD query failed");
  RequireIdentity(owned, program, map_id, query);
  RequireFtrace(listing, owned.address);
}

}

struct FailKernTestAccess {
  static void Prepare(FailKern& injection) {
    injection.filter_map_ = {901, 1};
    injection.bio_probe_ = identity;
  }
  static void ForgetIdentity(FailKern& injection) {
    injection.bio_probe_.reset();
  }
  static void Publish(BPFKIServiceImpl& service, std::unique_ptr<FailKern> injection) {
    const std::vector<FailKern::Frame> frames;
    const auto key = std::to_string(absl::Hash<std::vector<FailKern::Frame>>{}(frames));
    service.bpfki_map_.emplace(key, std::move(injection));
  }
  static BPFKI* Cached(BPFKIServiceImpl& service) {
    return service.bpfki_map_.empty() ? nullptr : service.bpfki_map_.begin()->second.get();
  }
};

}

namespace {

struct Fixture {
  std::shared_ptr<spdlog::logger> logger = std::make_shared<spdlog::logger>(
      "update-test", std::make_shared<spdlog::sinks::null_sink_mt>());
  std::vector<std::string> headers;
  std::vector<bpfki::FailKern::Frame> frames;
  bpfki::BPFKIServiceImpl service{logger};
  bpfki::FailKernRequest request;
  bpfki::StatusResponse response;
  bpfki::FailKern* injection;

  explicit Fixture(bpfki::FailKern::Type type) {
    auto owned = std::make_unique<bpfki::FailKern>(logger, type, headers, frames);
    injection = owned.get();
    bpfki::FailKernTestAccess::Prepare(*injection);
    bpfki::FailKernTestAccess::Publish(service, std::move(owned));
    request.set_pid(1234);
    request.set_ftype(static_cast<bpfki::FailKernRequest::FAILTYPE>(type));
    request.set_probability(1);
    filters.clear();
    listing = ftrace;
    query = {17, true, "should_fail_bio", 0, identity.address};
    program = {17, {23}};
    map_id = 23;
    query_failure = write_failure = false;
    checks = writes = deletes = 0;
  }

  grpc::Status Set() {
    return service.FailMMOrBIO(nullptr, &request, &response);
  }

  void RejectedWithoutWrite(const std::string& name) {
    const auto previous = filters;
    const auto write_count = writes;
    auto status = Set();
    Check(status.error_code() == grpc::StatusCode::FAILED_PRECONDITION,
          name + " did not return FAILED_PRECONDITION");
    Check(filters == previous && writes == write_count, name + " touched filters");
    Check(bpfki::FailKernTestAccess::Cached(service) == injection, name + " replaced the cached instance");
  }
};

void BioUpdates() {
  Fixture test(bpfki::FailKern::BIO);
  Check(test.Set().ok() && writes == 1 && checks == 1 && filters.size() == 1,
        "live FTRACE did not permit a filter write");
  test.request.set_pid(5678);
  Check(test.Set().ok() && checks == 2 && filters.size() == 2,
        "cached BIO update was not rechecked");
  for (const auto& mode : {"", "[OPTIMIZED]", "[FTRACE][DISABLED]", "[FTRACE][GONE]",
                           "[FTRACE][UNKNOWN]", "[FTRACE]garbage"}) {
    listing = "ffffffff81001004 k should_fail_bio+0x4 " + std::string(mode) + "\n";
    test.RejectedWithoutWrite("incompatible mode");
  }
  listing = ftrace + "ffffffff81001004 k should_fail_bio+0x4 [OPTIMIZED]\n";
  test.RejectedWithoutWrite("mixed aggregate mode");
  listing = ftrace.substr(0, ftrace.size() - 1);
  test.RejectedWithoutWrite("truncated metadata");
  listing.clear();
  test.RejectedWithoutWrite("missing metadata");
  listing = ftrace;
  query.program_id = 99;
  test.RejectedWithoutWrite("reused perf FD");
  query.program_id = 17;
  program.map_ids = {24};
  test.RejectedWithoutWrite("foreign ctxs map");
  program.map_ids = {23};
  query_failure = true;
  test.RejectedWithoutWrite("transient query failure");
  test.request.clear_ftype();
  const auto check_count = checks;
  Check(test.service.RecoverMMOrBIO(nullptr, &test.request, &test.response).ok() &&
        checks == check_count && filters.size() == 1 && deletes == 1,
        "recovery with omitted type did not bypass metadata checks");
  test.request.set_pid(1234);
  Check(test.service.RecoverMMOrBIO(nullptr, &test.request, &test.response).ok() &&
        checks == check_count && filters.empty() && deletes == 2 &&
        bpfki::FailKernTestAccess::Cached(test.service) == nullptr,
        "last recovery did not remove the cached instance");
}

void FirstWritesAndTypes() {
  for (auto type : {bpfki::FailKern::SLAB, bpfki::FailKern::PAGE, bpfki::FailKern::BIO}) {
    Fixture test(type);
    Check(test.Set().ok(), "initial matching fault type failed");
    const auto check_count = checks;
    test.request.set_ftype(type == bpfki::FailKern::BIO ? bpfki::FailKernRequest::PAGE
                                                       : bpfki::FailKernRequest::BIO);
    test.RejectedWithoutWrite("same-callchain fault type mismatch");
    Check(checks == check_count, "type mismatch reached the BIO reader");
    test.request.clear_ftype();
    query_failure = true;
    Check(test.service.RecoverMMOrBIO(nullptr, &test.request, &test.response).ok() &&
          filters.empty() && checks == check_count,
          "type mismatch prevented recovery");
  }
  {
    Fixture test(bpfki::FailKern::BIO);
    test.request.set_probability(0);
    listing = "ffffffff81001004 k should_fail_bio+0x4\n";
    test.RejectedWithoutWrite("zero-probability unsupported BIO");
    listing = ftrace;
    bpfki::FailKernTestAccess::ForgetIdentity(*test.injection);
    test.RejectedWithoutWrite("missing initial BIO identity");
  }
  for (auto type : {bpfki::FailKern::SLAB, bpfki::FailKern::PAGE}) {
    Fixture test(type);
    query_failure = true;
    Check(test.Set().ok() && writes == 1 && checks == 0,
          "non-BIO update unexpectedly depends on BIO metadata");
    write_failure = true;
    const auto previous = filters;
    Check(test.Set().error_code() == grpc::StatusCode::INTERNAL && filters == previous,
          "ordinary map failure did not remain INTERNAL");
  }
}

}

int main() {
  try {
    BioUpdates();
    FirstWritesAndTypes();
    std::cout << "PASS: actual FailKern update and cached RPC branches, with mocked metadata and map writes.\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
