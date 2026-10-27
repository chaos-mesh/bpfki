#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cctype>
#include <cstring>
#include <limits>
#include <sstream>

#include <fcntl.h>
#include <linux/magic.h>
#include <linux/nsfs.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>

#include <absl/hash/hash.h>

#include "filter_layout.h"
#include "service.h"

namespace bpfki {
namespace {

bool IsHex(char value) {
  return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f');
}

bool IsOpaqueID(const std::string& value) {
  return value.size() == 32 &&
         std::all_of(value.begin(), value.end(), IsHex);
}

bool IsBootID(const std::string& value) {
  if (value.size() != 36)
    return false;
  for (size_t i = 0; i < value.size(); ++i) {
    if (i == 8 || i == 13 || i == 18 || i == 23) {
      if (value[i] != '-')
        return false;
    } else if (!IsHex(value[i])) {
      return false;
    }
  }
  return true;
}

grpc::Status RandomID(std::string* id) {
  std::array<unsigned char, 16> bytes;
  size_t offset = 0;
  while (offset < bytes.size()) {
    const auto count = getrandom(bytes.data() + offset, bytes.size() - offset, 0);
    if (count < 0 && errno == EINTR)
      continue;
    if (count <= 0)
      return {grpc::StatusCode::UNAVAILABLE, "cannot read OS entropy for kernel fault identity"};
    offset += static_cast<size_t>(count);
  }
  constexpr char hex[] = "0123456789abcdef";
  id->clear();
  for (const auto byte : bytes) {
    id->push_back(hex[byte >> 4]);
    id->push_back(hex[byte & 15]);
  }
  return grpc::Status::OK;
}

grpc::Status ReadProcText(const std::string& path, std::string* text) {
  const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    const int error = errno;
    return {error == ENOENT ? grpc::StatusCode::NOT_FOUND : grpc::StatusCode::UNAVAILABLE,
            "read " + path + ": " + std::strerror(error)};
  }
  text->clear();
  char buffer[4096];
  grpc::Status status;
  for (;;) {
    const auto count = read(fd, buffer, sizeof(buffer));
    if (count < 0 && errno == EINTR)
      continue;
    if (count < 0) {
      status = {grpc::StatusCode::UNAVAILABLE, "read " + path + ": " + std::strerror(errno)};
      break;
    }
    if (count == 0)
      break;
    text->append(buffer, static_cast<size_t>(count));
    if (text->size() > 16384) {
      status = {grpc::StatusCode::UNAVAILABLE, "oversized proc metadata: " + path};
      break;
    }
  }
  close(fd);
  return status;
}

grpc::Status ReadPIDNamespace(const char* path, uint64_t* inode) {
  const int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return {grpc::StatusCode::UNAVAILABLE,
            std::string("open ") + path + ": " + std::strerror(errno)};
  struct stat info = {};
  struct statfs filesystem = {};
  grpc::Status status;
  if (fstat(fd, &info) != 0) {
    status = {grpc::StatusCode::UNAVAILABLE,
              std::string("fstat ") + path + ": " + std::strerror(errno)};
  } else if (fstatfs(fd, &filesystem) != 0) {
    status = {grpc::StatusCode::UNAVAILABLE,
              std::string("fstatfs ") + path + ": " + std::strerror(errno)};
  } else if (filesystem.f_type != NSFS_MAGIC || info.st_ino == 0) {
    status = {grpc::StatusCode::FAILED_PRECONDITION,
              std::string("not a namespace file: ") + path};
  } else {
    const int type = ioctl(fd, NS_GET_NSTYPE);
    if (type < 0)
      status = {grpc::StatusCode::UNAVAILABLE,
                std::string("NS_GET_NSTYPE ") + path + ": " + std::strerror(errno)};
    else if (type != CLONE_NEWPID)
      status = {grpc::StatusCode::FAILED_PRECONDITION,
                std::string("not a PID namespace: ") + path};
  }
  close(fd);
  if (!status.ok())
    return status;
  *inode = info.st_ino;
  return grpc::Status::OK;
}

grpc::Status ValidateFault(const FailKernRequest& fault) {
  if (fault.pid() == 0 || fault.pid() > static_cast<uint32_t>(std::numeric_limits<int>::max()) ||
      fault.tid() != 0)
    return {grpc::StatusCode::INVALID_ARGUMENT, "owned kernel faults require a positive PID and tid=0"};
  if (fault.ftype() != FailKernRequest::SLAB && fault.ftype() != FailKernRequest::PAGE &&
      fault.ftype() != FailKernRequest::BIO)
    return {grpc::StatusCode::INVALID_ARGUMENT, "unknown kernel fault type"};
  try {
    filter_layout::ParseCondition(fault.probability(), fault.times());
    if (fault.callchain_size() >= std::numeric_limits<int>::max() - 1)
      throw std::invalid_argument("too many callchain frames");
    const auto size = static_cast<size_t>(fault.callchain_size());
    filter_layout::ValueSize(size == 1 && fault.callchain(0).funcname().empty() ? 1 : size + 1);
    for (int i = 0; i + 1 < fault.callchain_size(); ++i) {
      if (fault.callchain(i).funcname().empty())
        throw std::invalid_argument("only the last callchain frame may omit funcname");
    }
  } catch (const std::invalid_argument& error) {
    return {grpc::StatusCode::INVALID_ARGUMENT, error.what()};
  }
  return grpc::Status::OK;
}

}

BPFKIServiceImpl::BPFKIServiceImpl(const std::shared_ptr<spdlog::logger>& logger)
    : BPFKIServiceImpl(logger, ReadSession) {}

BPFKIServiceImpl::BPFKIServiceImpl(const std::shared_ptr<spdlog::logger>& logger,
                                   SessionReader read_session)
    : logger_(logger), now_(Clock::now), read_process_start_(ReadProcessStart),
      kernel_factory_([this](FailKern::Type type, std::vector<std::string>& headers,
                             std::vector<FailKern::Frame>& callchain) {
        return std::make_unique<FailKern>(logger_, type, headers, callchain);
      }) {
  kernel_session_status_ = read_session(&kernel_session_);
  if (!kernel_session_status_.ok())
    logger_->error("Owned kernel faults unavailable: {}", kernel_session_status_.error_message());
}

BPFKIServiceImpl::~BPFKIServiceImpl() = default;

grpc::Status BPFKIServiceImpl::ParseProcessStart(const std::string& stat, uint32_t pid,
                                               uint64_t* start_time) {
  const auto malformed = grpc::Status(grpc::StatusCode::UNAVAILABLE, "malformed process stat metadata");
  const auto prefix = std::to_string(pid) + " (";
  const auto end = stat.rfind(')');
  if (stat.compare(0, prefix.size(), prefix) != 0 || end == std::string::npos ||
      end < prefix.size() || end + 1 >= stat.size() || stat[end + 1] != ' ')
    return malformed;
  std::istringstream fields(stat.substr(end + 1));
  std::string token;
  if (!(fields >> token) || token.size() != 1 || !std::isalpha(static_cast<unsigned char>(token[0])))
    return malformed;
  for (int field = 4; field <= 21; ++field) {
    if (!(fields >> token))
      return malformed;
    const size_t first = token[0] == '-' ? 1 : 0;
    if (first == token.size() || !std::all_of(token.begin() + first, token.end(),
                                             [](char c) { return c >= '0' && c <= '9'; }))
      return malformed;
  }
  if (!(fields >> token))
    return malformed;
  uint64_t ticks = 0;
  const auto parsed = std::from_chars(token.data(), token.data() + token.size(), ticks);
  if (parsed.ec != std::errc() || parsed.ptr != token.data() + token.size() || ticks == 0)
    return malformed;
  *start_time = ticks;
  return grpc::Status::OK;
}

grpc::Status BPFKIServiceImpl::ValidatePIDNamespaceView(uint64_t expected, uint64_t self,
                                                     uint64_t proc_init) {
  // Linux nsfs PID_NS_INIT_INO, formerly PROC_PID_INIT_INO.
  constexpr uint64_t initial_pid_namespace = 0xEFFFFFFCULL;
  if (expected != initial_pid_namespace || self != initial_pid_namespace ||
      proc_init != initial_pid_namespace)
    return {grpc::StatusCode::FAILED_PRECONDITION,
            "owned kernel faults require the initial PID namespace and its procfs"};
  return grpc::Status::OK;
}

grpc::Status BPFKIServiceImpl::ReadProcessStart(uint32_t pid, uint64_t pid_namespace,
                                              std::optional<uint64_t>* start_time) {
  start_time->reset();
  uint64_t self = 0, proc_init = 0;
  auto status = ReadPIDNamespace("/proc/self/ns/pid", &self);
  if (!status.ok())
    return status;
  status = ReadPIDNamespace("/proc/1/ns/pid", &proc_init);
  if (!status.ok())
    return status;
  status = ValidatePIDNamespaceView(pid_namespace, self, proc_init);
  if (!status.ok())
    return status;
  std::string stat;
  status = ReadProcText("/proc/" + std::to_string(pid) + "/stat", &stat);
  if (status.error_code() == grpc::StatusCode::NOT_FOUND)
    return grpc::Status::OK;
  if (!status.ok())
    return status;
  uint64_t ticks = 0;
  status = ParseProcessStart(stat, pid, &ticks);
  if (status.ok())
    *start_time = ticks;
  return status;
}

grpc::Status BPFKIServiceImpl::ReadSession(KernelFaultSession* session) {
  std::string boot_id;
  auto status = ReadProcText("/proc/sys/kernel/random/boot_id", &boot_id);
  if (!status.ok())
    return {grpc::StatusCode::UNAVAILABLE, status.error_message()};
  if (!boot_id.empty() && boot_id.back() == '\n')
    boot_id.pop_back();
  if (!IsBootID(boot_id))
    return {grpc::StatusCode::UNAVAILABLE, "malformed node boot ID"};
  uint64_t pid_namespace = 0;
  status = ReadPIDNamespace("/proc/self/ns/pid", &pid_namespace);
  if (!status.ok())
    return status;
  const auto pid = static_cast<uint32_t>(getpid());
  std::optional<uint64_t> start_time;
  status = ReadProcessStart(pid, pid_namespace, &start_time);
  if (!status.ok())
    return status;
  if (!start_time)
    return {grpc::StatusCode::UNAVAILABLE, "service process is absent from procfs"};
  std::string instance;
  status = RandomID(&instance);
  if (!status.ok())
    return status;
  session->set_instance(instance);
  session->set_boot_id(boot_id);
  session->set_pid(pid);
  session->set_start_time(*start_time);
  session->set_pid_namespace(pid_namespace);
  return grpc::Status::OK;
}

void BPFKIServiceImpl::Reservation::Prepare() {
  headers.assign(fault.headers().begin(), fault.headers().end());
  callchain.clear();
  callchain.reserve(fault.callchain_size());
  for (const auto& frame : fault.callchain())
    callchain.emplace_back(frame.funcname(), frame.parameters(), frame.predicate());
}

grpc::Status BPFKIServiceImpl::ValidateNode(const std::string& node_boot_id) const {
  if (!kernel_session_status_.ok())
    return kernel_session_status_;
  if (!IsBootID(node_boot_id))
    return {grpc::StatusCode::INVALID_ARGUMENT, "a valid current node boot ID is required"};
  if (node_boot_id != kernel_session_.boot_id())
    return {grpc::StatusCode::FAILED_PRECONDITION, "request node boot ID differs from this service"};
  return grpc::Status::OK;
}

grpc::Status BPFKIServiceImpl::ValidateReference(const KernelFaultReference& request) const {
  auto status = ValidateNode(request.node_boot_id());
  if (!status.ok())
    return status;
  const auto& handle = request.handle();
  const auto& session = handle.session();
  if (!request.has_handle() || !handle.has_session() || !IsOpaqueID(handle.id()) ||
      !IsOpaqueID(session.instance()) || !IsBootID(session.boot_id()) || session.pid() == 0 ||
      session.pid() > static_cast<uint32_t>(std::numeric_limits<int>::max()) ||
      session.start_time() == 0 || session.pid_namespace() == 0)
    return {grpc::StatusCode::INVALID_ARGUMENT, "malformed kernel fault handle or session"};
  return grpc::Status::OK;
}

grpc::Status BPFKIServiceImpl::RequireSession(const KernelFaultSession& session) const {
  if (session.instance() != kernel_session_.instance())
    return {grpc::StatusCode::ABORTED, "kernel fault belongs to another service instance"};
  if (session.boot_id() != kernel_session_.boot_id() || session.pid() != kernel_session_.pid() ||
      session.start_time() != kernel_session_.start_time() ||
      session.pid_namespace() != kernel_session_.pid_namespace())
    return {grpc::StatusCode::FAILED_PRECONDITION, "kernel fault session witness does not match"};
  return grpc::Status::OK;
}

grpc::Status BPFKIServiceImpl::RequireTargetProcess(const Reservation& reservation) const {
  std::optional<uint64_t> start_time;
  auto status = read_process_start_(reservation.fault.pid(), kernel_session_.pid_namespace(), &start_time);
  if (!status.ok())
    return status;
  if (!start_time || *start_time != reservation.target_start_time)
    return {grpc::StatusCode::NOT_FOUND, "reserved target process is absent or its PID was reused"};
  return grpc::Status::OK;
}

grpc::Status BPFKIServiceImpl::ProveServiceGone(const KernelFaultSession& session) const {
  if (session.boot_id() != kernel_session_.boot_id())
    return grpc::Status::OK;
  if (session.pid_namespace() != kernel_session_.pid_namespace())
    return {grpc::StatusCode::FAILED_PRECONDITION, "cannot verify the old service in another PID namespace"};
  std::optional<uint64_t> start_time;
  auto status = read_process_start_(session.pid(), session.pid_namespace(), &start_time);
  if (!status.ok())
    return status;
  if (start_time && *start_time == session.start_time())
    return {grpc::StatusCode::FAILED_PRECONDITION, "the old service process is still alive"};
  return grpc::Status::OK;
}

size_t BPFKIServiceImpl::PurgeExpiredReservations() {
  const auto now = now_();
  size_t pending = 0;
  for (auto it = kernel_faults_.begin(); it != kernel_faults_.end();) {
    if (!it->second.active && now >= it->second.expires_at) {
      it = kernel_faults_.erase(it);
    } else {
      pending += !it->second.active;
      ++it;
    }
  }
  return pending;
}

grpc::Status BPFKIServiceImpl::ReserveKernelFault(grpc::ServerContext*,
                                                const ReserveKernelFaultRequest* request,
                                                KernelFaultHandle* response) {
  response->Clear();
  auto status = ValidateNode(request->node_boot_id());
  if (!status.ok())
    return status;
  if (!request->has_fault())
    return {grpc::StatusCode::INVALID_ARGUMENT, "a kernel fault request is required"};
  status = ValidateFault(request->fault());
  if (!status.ok())
    return status;
  std::optional<uint64_t> target_start;
  status = read_process_start_(request->fault().pid(), kernel_session_.pid_namespace(), &target_start);
  if (!status.ok())
    return status;
  if (!target_start)
    return {grpc::StatusCode::NOT_FOUND, "target process is absent"};
  std::lock_guard<std::mutex> guard(kernel_faults_mtx_);
  if (PurgeExpiredReservations() >= max_pending_reservations_)
    return {grpc::StatusCode::RESOURCE_EXHAUSTED, "too many unarmed kernel fault reservations"};
  for (int attempt = 0; attempt < 4; ++attempt) {
    std::string id;
    status = RandomID(&id);
    if (!status.ok())
      return status;
    if (kernel_faults_.try_emplace(id, request->fault(), *target_start,
                                    now_() + reservation_lifetime_).second) {
      response->set_id(id);
      *response->mutable_session() = kernel_session_;
      return grpc::Status::OK;
    }
  }
  return {grpc::StatusCode::UNAVAILABLE, "cannot allocate a unique kernel fault handle"};
}

grpc::Status BPFKIServiceImpl::ArmKernelFault(grpc::ServerContext*,
                                            const KernelFaultReference* request,
                                            StatusResponse* response) {
  response->Clear();
  auto status = ValidateReference(*request);
  if (!status.ok())
    return status;
  status = RequireSession(request->handle().session());
  if (!status.ok())
    return status;
  std::lock_guard<std::mutex> guard(kernel_faults_mtx_);
  PurgeExpiredReservations();
  const auto found = kernel_faults_.find(request->handle().id());
  if (found == kernel_faults_.end())
    return {grpc::StatusCode::NOT_FOUND, "kernel fault reservation is absent or expired"};
  auto& reservation = found->second;
  if (reservation.active)
    return grpc::Status::OK;
  status = RequireTargetProcess(reservation);
  if (!status.ok())
    return status;
  try {
    reservation.Prepare();
    auto active = kernel_factory_(static_cast<FailKern::Type>(reservation.fault.ftype()),
                                   reservation.headers, reservation.callchain);
    if (!active || active->init() != 0)
      return {grpc::StatusCode::INTERNAL, "cannot initialize the owned kernel fault"};
    status = RequireTargetProcess(reservation);
    if (!status.ok())
      return status;
    if (active->update_inject_cond(&reservation.fault) != 1)
      return {grpc::StatusCode::INTERNAL, "cannot install the owned kernel fault filter"};
    reservation.active = std::move(active);
  } catch (const UnsupportedInjection& error) {
    return {grpc::StatusCode::FAILED_PRECONDITION, error.what()};
  } catch (const std::exception& error) {
    return {grpc::StatusCode::INTERNAL, error.what()};
  }
  return grpc::Status::OK;
}

grpc::Status BPFKIServiceImpl::ReleaseKernelFault(grpc::ServerContext*,
                                                const KernelFaultReference* request,
                                                ReleaseKernelFaultResponse* response) {
  response->Clear();
  auto status = ValidateReference(*request);
  if (!status.ok())
    return status;
  if (request->handle().session().instance() != kernel_session_.instance()) {
    status = ProveServiceGone(request->handle().session());
    if (!status.ok())
      return status;
    response->set_outcome(ReleaseKernelFaultResponse::SERVICE_GONE);
    return grpc::Status::OK;
  }
  status = RequireSession(request->handle().session());
  if (!status.ok())
    return status;
  std::lock_guard<std::mutex> guard(kernel_faults_mtx_);
  PurgeExpiredReservations();
  response->set_outcome(kernel_faults_.erase(request->handle().id()) == 1
                            ? ReleaseKernelFaultResponse::RELEASED
                            : ReleaseKernelFaultResponse::ABSENT);
  return grpc::Status::OK;
}

grpc::Status BPFKIServiceImpl::SetTime(const std::string& type,
                                       const BumpTimeRequest* request,
                                       StatusResponse* response) {
  std::unique_ptr<BPFKI> bpfki = nullptr;
  auto it = bpfki_map_.find(type);
  if (it == bpfki_map_.end()) {
    bpfki = createBPFKI("BumpTime", logger_, type);
    try {
      bpfki->init();
    } catch (const std::invalid_argument& ia) {
      logger_->error("Internal error invalid argument: {}", ia.what());
      return grpc::Status(grpc::StatusCode::INTERNAL, ia.what());
    }
  } else {
    bpfki = std::move(it->second);
  }
  try {
    auto left_nr_filters = bpfki->update_inject_cond(
      reinterpret_cast<const void*>(request));
    logger_->info("left_nr_filters: {}", left_nr_filters);
  } catch (const std::invalid_argument& ia) {
    logger_->error("Internal error invalid argument: {}", ia.what());
    return grpc::Status(grpc::StatusCode::INTERNAL, ia.what());
  }
  bpfki_map_[type] = std::move(bpfki);
  return grpc::Status::OK;
}

grpc::Status BPFKIServiceImpl::RecoverTime(const std::string& type,
                                           const BumpTimeRequest *request,
                                           StatusResponse* response) {
  auto it = bpfki_map_.find(type);
  if (it == bpfki_map_.end())
    return grpc::Status::OK;
  try {
    auto left_nr_filters = it->second->update_inject_cond(
      reinterpret_cast<const void*>(request), true);
    logger_->info("left_nr_filters: {}", left_nr_filters);
    if (left_nr_filters == 0)
      bpfki_map_.erase(it);
  } catch (const std::invalid_argument& ia) {
    logger_->error("Internal error invalid argument: {}", ia.what());
    return grpc::Status(grpc::StatusCode::INTERNAL, ia.what());
  }
  return grpc::Status::OK;
}

grpc::Status BPFKIServiceImpl::SetTimeVal(grpc::ServerContext* context,
                                          const BumpTimeRequest* request,
                                          StatusResponse* response) {
  std::lock_guard<std::mutex> guard(bpfki_map_mtx_);
  return SetTime("gettimeofday", request, response);
}

grpc::Status BPFKIServiceImpl::RecoverTimeVal(grpc::ServerContext* context,
                                              const BumpTimeRequest* request,
                                              StatusResponse* response) {
  std::lock_guard<std::mutex> guard(bpfki_map_mtx_);
  return RecoverTime("gettimeofday", request, response);
}

grpc::Status BPFKIServiceImpl::SetTimeSpec(grpc::ServerContext* context,
                                           const BumpTimeRequest* request,
                                           StatusResponse* response) {
  std::lock_guard<std::mutex> guard(bpfki_map_mtx_);
  return RecoverTime("clock_gettime", request, response);
}

grpc::Status BPFKIServiceImpl::RecoverTimeSpec(grpc::ServerContext* context,
                                               const BumpTimeRequest* request,
                                               StatusResponse* response) {
  std::lock_guard<std::mutex> guard(bpfki_map_mtx_);
  return RecoverTime("clock_gettime", request, response);
}

grpc::Status BPFKIServiceImpl::FailMMOrBIO(grpc::ServerContext *context,
                                           const FailKernRequest *request,
                                           StatusResponse *response) {
  std::vector<std::string> headers;
  int header_size = request->headers_size();
  for (int i = 0; i < header_size; i++) {
    headers.push_back(request->headers(i));
  }
  std::vector<FailKern::Frame> callchain;
  int callchain_size = request->callchain_size();
  for (int i = 0; i < callchain_size; i++) {
    auto frame = request->callchain(i);
    if (i != callchain_size - 1 && frame.funcname() == "")
      throw std::invalid_argument("");
    callchain.push_back(FailKern::Frame(frame.funcname(),
                                        frame.parameters(),
                                        frame.predicate()));
  }
  auto k = std::to_string(absl::Hash<std::vector<FailKern::Frame>>{}(callchain));
  std::unique_ptr<BPFKI> new_bpfki;
  BPFKI* bpfki = nullptr;
  std::lock_guard<std::mutex> guard(bpfki_map_mtx_);
  auto it = bpfki_map_.find(k);
  if (it == bpfki_map_.end()) {
    auto type = static_cast<const FailKern::Type>(request->ftype());
    new_bpfki = createBPFKI("FailKern", logger_, type, headers, callchain);
    bpfki = new_bpfki.get();
    try {
      bpfki->init();
    } catch (const UnsupportedInjection& error) {
      logger_->error("Injection precondition failed: {}", error.what());
      return grpc::Status(grpc::StatusCode::FAILED_PRECONDITION, error.what());
    } catch(const std::invalid_argument& ia) {
      logger_->error("Internal error invalid argument: {}", ia.what());
      return grpc::Status(grpc::StatusCode::INTERNAL, ia.what());
    }
  } else {
    bpfki = it->second.get();
  }
  try {
    auto left_nr_filters = bpfki->update_inject_cond(
      reinterpret_cast<const void*>(request));
    logger_->info("left_nr_filters: {}", left_nr_filters);
  } catch (const UnsupportedInjection& error) {
    logger_->error("Injection precondition failed: {}", error.what());
    return grpc::Status(grpc::StatusCode::FAILED_PRECONDITION, error.what());
  } catch (const std::invalid_argument& ia) {
    logger_->error("Internal error invalid argument: {}", ia.what());
    return grpc::Status(grpc::StatusCode::INTERNAL, ia.what());
  }
  if (new_bpfki)
    bpfki_map_.emplace(k, std::move(new_bpfki));
  return grpc::Status::OK;
}

grpc::Status BPFKIServiceImpl::RecoverMMOrBIO(grpc::ServerContext* context,
                                              const FailKernRequest* request,
                                              StatusResponse* response) {
  std::vector<FailKern::Frame> callchain;
  int callchain_size = request->callchain_size();
  for (int i = 0; i < callchain_size; i++) {
    auto frame = request->callchain(i);
    if (i != callchain_size - 1 && frame.funcname() == "")
      throw std::invalid_argument("");
    callchain.push_back(FailKern::Frame(frame.funcname(),
                                        frame.parameters(),
                                        frame.predicate()));
  }
  auto k = std::to_string(absl::Hash<std::vector<FailKern::Frame>>{}(callchain));
  std::unique_ptr<BPFKI> bpfki = nullptr;
  std::lock_guard<std::mutex> guard(bpfki_map_mtx_);
  auto it = bpfki_map_.find(k);
  if (it == bpfki_map_.end())
    return grpc::Status::OK;
  try {
    auto left_nr_filters = it->second->update_inject_cond(
      reinterpret_cast<const void*>(request), true);
    logger_->info("left_nr_filters: {}", left_nr_filters);
    if (left_nr_filters == 0)
      bpfki_map_.erase(it);
  } catch (const std::invalid_argument& ia) {
    logger_->error("Internal error invalid argument: {}", ia.what());
    return grpc::Status(grpc::StatusCode::INTERNAL, ia.what());
  }
  return grpc::Status::OK;
}

grpc::Status BPFKIServiceImpl::FailSyscall(grpc::ServerContext* context,
                                           const FailSyscallRequest* request,
                                           StatusResponse* response) {
  return grpc::Status::OK;
}

grpc::Status BPFKIServiceImpl::RecoverSyscall(grpc::ServerContext* context,
                                              const FailSyscallRequest* request,
                                              StatusResponse* response) {
  return grpc::Status::OK;
}

};
