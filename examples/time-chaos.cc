#include <iostream>
#include <chrono>
#include <thread>

#include <gflags/gflags.h>
#include <grpcpp/grpcpp.h>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include "bpfki.grpc.pb.h"

using namespace std::chrono_literals;

class BPFKIClient final: public bpfki::BPFKIService::Service {
 public:
  BPFKIClient(std::shared_ptr<grpc::Channel> channel,
              const std::shared_ptr<spdlog::logger>& logger)
    : stub_(bpfki::BPFKIService::NewStub(channel)), logger_(logger) {}

  void SetTime(int type, uint32_t pid, uint32_t tid,
               int32_t sec, int32_t ssec, float pct) {
    bpfki::BumpTimeRequest req;
    req.set_pid(pid);
    req.set_tid(tid);
    req.set_second(sec);
    req.set_subsecond(ssec);
    req.set_probability(pct);
    grpc::ClientContext ctx;
    bpfki::StatusResponse resp;
    grpc::Status status;
    if (type == 0)
      status = stub_->SetTimeVal(&ctx, req, &resp);
    else if (type == 1)
      status = stub_->SetTimeSpec(&ctx, req, &resp);
    else
      logger_->error("Unknown");

    if (!status.ok())
      logger_->error("SetTime PRC failed");
  }

  void RecoverTime(int type, uint32_t pid, uint32_t tid) {
    bpfki::BumpTimeRequest req;
    req.set_pid(pid);
    req.set_tid(tid);
    grpc::ClientContext ctx;
    bpfki::StatusResponse resp;
    grpc::Status status;
    if (type == 0)
      status = stub_->RecoverTimeVal(&ctx, req, &resp);
    else if (type == 1)
      status = stub_->RecoverTimeSpec(&ctx, req, &resp);
    else
      logger_->error("Unknown");
    if (!status.ok())
      logger_->error("Recover PRC failed");
  }

 private:
  std::unique_ptr<bpfki::BPFKIService::Stub> stub_;
  const std::shared_ptr<spdlog::logger>& logger_;
};

DEFINE_uint32(pid, -1, "root ns pid");
DEFINE_uint32(tid, -1, "root ns tid");
DEFINE_int32(sec, 0, "skew sec");
DEFINE_int32(ssec, 0, "skew ssec");
DEFINE_int32(pct, 0, "probability");
DEFINE_int32(type, 0, "time syscall (0: gettimeofday, 1: clock_gettime)");

int main(int argc, char *argv[]) {
  gflags::ParseCommandLineFlags(&argc, &argv, true);
  auto logger = spdlog::stdout_color_mt("console");
  BPFKIClient cli(grpc::CreateChannel(
    "localhost:50051", grpc::InsecureChannelCredentials()),
    logger);
  cli.SetTime(FLAGS_type, FLAGS_pid, FLAGS_tid,
              FLAGS_sec, FLAGS_ssec, FLAGS_pct);
  std::this_thread::sleep_for(60s);
  cli.RecoverTime(FLAGS_type, FLAGS_pid, FLAGS_tid);
  return 0;
}
