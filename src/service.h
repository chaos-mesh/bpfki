#pragma once

#include <iostream>
#include <mutex>

#include <grpcpp/grpcpp.h>
#include <spdlog/spdlog.h>

#include "bpfki.grpc.pb.h"
#include "bpfki.h"

namespace bpfki {

class BPFKIServiceImpl final: public BPFKIService::Service {
 public:
  explicit BPFKIServiceImpl(const std::shared_ptr<spdlog::logger>& logger);
  ~BPFKIServiceImpl();
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
  grpc::Status SetTime(const std::string& type,
                       const BumpTimeRequest* request,
                       StatusResponse* response);
  grpc::Status RecoverTime(const std::string& type,
                           const BumpTimeRequest *request,
                           StatusResponse* response);
 private:
  const std::shared_ptr<spdlog::logger>& logger_;
  std::map<std::string, std::unique_ptr<BPFKI>> bpfki_map_;
  std::mutex bpfki_map_mtx_;
};
       
};
