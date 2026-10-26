#pragma once

#include <chrono>
#include <functional>
#include <map>
#include <mutex>
#include <optional>

#include <grpcpp/grpcpp.h>
#include <spdlog/spdlog.h>

#include "bpfki.grpc.pb.h"
#include "bpfki.h"

namespace bpfki {

class BPFKIServiceImpl final: public BPFKIService::Service {
 public:
  explicit BPFKIServiceImpl(const std::shared_ptr<spdlog::logger>& logger);
  ~BPFKIServiceImpl();
  grpc::Status ReserveKernelFault(grpc::ServerContext* context,
                                  const ReserveKernelFaultRequest* request,
                                  KernelFaultHandle* response) override;
  grpc::Status ArmKernelFault(grpc::ServerContext* context,
                              const KernelFaultReference* request,
                              StatusResponse* response) override;
  grpc::Status ReleaseKernelFault(grpc::ServerContext* context,
                                  const KernelFaultReference* request,
                                  ReleaseKernelFaultResponse* response) override;
  grpc::Status SetTimeVal(grpc::ServerContext* context,
                          const BumpTimeRequest* request,
                          StatusResponse* response) override;
  grpc::Status RecoverTimeVal(grpc::ServerContext* context,
                              const BumpTimeRequest* request,
                              StatusResponse* response) override;
  grpc::Status SetTimeSpec(grpc::ServerContext* context,
                           const BumpTimeRequest* request,
                           StatusResponse* response) override;
  grpc::Status RecoverTimeSpec(grpc::ServerContext* context,
                               const BumpTimeRequest* request,
                               StatusResponse* response) override;
  grpc::Status FailMMOrBIO(grpc::ServerContext* context,
                           const FailKernRequest* request,
                           StatusResponse* response) override;
  grpc::Status RecoverMMOrBIO(grpc::ServerContext* context,
                              const FailKernRequest* request,
                              StatusResponse* response) override;
  grpc::Status FailSyscall(grpc::ServerContext* context,
                           const FailSyscallRequest* request,
                           StatusResponse* response) override;
  grpc::Status RecoverSyscall(grpc::ServerContext* context,
                              const FailSyscallRequest* request,
                              StatusResponse* response) override;

 private:
  friend struct FailKernTestAccess;
  friend struct KernelFaultTestAccess;

  using SessionReader = grpc::Status (*)(KernelFaultSession*);
  BPFKIServiceImpl(const std::shared_ptr<spdlog::logger>& logger, SessionReader read_session);

  using Clock = std::chrono::steady_clock;
  struct Reservation {
    Reservation(const FailKernRequest& request, uint64_t target_start, Clock::time_point expires)
        : fault(request), target_start_time(target_start), expires_at(expires) {}
    void Prepare();

    const FailKernRequest fault;
    const uint64_t target_start_time;
    const Clock::time_point expires_at;
    std::vector<std::string> headers;
    std::vector<FailKern::Frame> callchain;
    std::unique_ptr<BPFKI> active;
  };
  using KernelFactory = std::function<std::unique_ptr<BPFKI>(
      FailKern::Type, std::vector<std::string>&, std::vector<FailKern::Frame>&)>;
  using ProcessReader = std::function<grpc::Status(
      uint32_t, uint64_t, std::optional<uint64_t>*)>;

  static grpc::Status ReadSession(KernelFaultSession* session);
  static grpc::Status ReadProcessStart(uint32_t pid, uint64_t pid_namespace,
                                       std::optional<uint64_t>* start_time);
  static grpc::Status ParseProcessStart(const std::string& stat, uint32_t pid,
                                        uint64_t* start_time);
  grpc::Status ValidateNode(const std::string& node_boot_id) const;
  grpc::Status ValidateReference(const KernelFaultReference& request) const;
  grpc::Status RequireSession(const KernelFaultSession& session) const;
  grpc::Status RequireTargetProcess(const Reservation& reservation) const;
  grpc::Status ProveServiceGone(const KernelFaultSession& session) const;
  size_t PurgeExpiredReservations();

  grpc::Status SetTime(const std::string& type,
                       const BumpTimeRequest* request,
                       StatusResponse* response);
  grpc::Status RecoverTime(const std::string& type,
                           const BumpTimeRequest *request,
                           StatusResponse* response);

  const std::shared_ptr<spdlog::logger>& logger_;
  std::map<std::string, std::unique_ptr<BPFKI>> bpfki_map_;
  std::mutex bpfki_map_mtx_;

  static constexpr auto reservation_lifetime_ = std::chrono::minutes(5);
  static constexpr size_t max_pending_reservations_ = 1024;
  KernelFaultSession kernel_session_;
  grpc::Status kernel_session_status_;
  std::function<Clock::time_point()> now_;
  ProcessReader read_process_start_;
  KernelFactory kernel_factory_;
  std::map<std::string, Reservation> kernel_faults_;
  std::mutex kernel_faults_mtx_;
};

};
