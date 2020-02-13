#include <iostream>
#include <chrono>
#include <thread>

#include <gflags/gflags.h>
#include <grpcpp/grpcpp.h>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include "bpfki.grpc.pb.h"

class BPFKIClient final: public bpfki::BPFKIService::Service {
 public:
  BPFKIClient(std::shared_ptr<grpc::Channel> channel,
              const std::shared_ptr<spdlog::logger>& logger)
    : stub_(bpfki::BPFKIService::NewStub(channel)), logger_(logger) {}

  void FailMMOrBIO(uint32_t pid, uint32_t tid, float pct) {
    bpfki::FailKernRequest req;
    grpc::ClientContext ctx;
    bpfki::StatusResponse resp;

    req.set_pid(pid);
    req.set_tid(tid);
    req.set_probability(pct);
    req.set_ftype(bpfki::FailKernRequest_FAILTYPE_PAGE);
    stub_->FailMMOrBIO(&ctx, req, &resp);
  }

  void RecoverMMOrBIO(uint32_t pid, uint32_t tid) {
    bpfki::FailKernRequest req;
    grpc::ClientContext ctx;
    bpfki::StatusResponse resp;

    req.set_pid(pid);
    req.set_tid(tid);
    stub_->RecoverMMOrBIO(&ctx, req, &resp);
  }

 private:
  std::unique_ptr<bpfki::BPFKIService::Stub> stub_;
  const std::shared_ptr<spdlog::logger>& logger_;
};

DEFINE_uint32(pid, 0, "root ns pid");
DEFINE_uint32(tid, 0, "root ns tid");
DEFINE_int32(pct, 0, "probability");
DEFINE_int32(action, 1, " (1: inject, 0: clear)");

int main(int argc, char *argv[]) {
  gflags::ParseCommandLineFlags(&argc, &argv, true);
  auto logger = spdlog::stdout_color_mt("console");
  BPFKIClient cli(grpc::CreateChannel(
    "localhost:50051", grpc::InsecureChannelCredentials()),
    logger);
  if (FLAGS_action == 1)
    cli.FailMMOrBIO(FLAGS_pid, FLAGS_tid, FLAGS_pct);
  else
    cli.RecoverMMOrBIO(FLAGS_pid, FLAGS_tid);
  return 0;
}
