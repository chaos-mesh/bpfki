#include <iostream>
#include <chrono>
#include <thread>

#include <grpcpp/grpcpp.h>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include "bpfki.grpc.pb.h"

class BPFKIClient final: public bpfki::BPFKIService::Service {
 public:
  BPFKIClient(std::shared_ptr<grpc::Channel> channel,
              const std::shared_ptr<spdlog::logger>& logger)
    : stub_(bpfki::BPFKIService::NewStub(channel)), logger_(logger) {}

  void FailMMOrBIO(void) {
    bpfki::FailKernRequest req;
    grpc::ClientContext ctx;
    bpfki::StatusResponse resp;

    req.add_headers("linux/blkdev.h");
    req.set_ftype(bpfki::FailKernRequest_FAILTYPE_BIO);
    auto frame = req.add_callchain();
    frame->set_predicate(R"(({struct gendisk *d = bio->bi_disk;
struct disk_part_tbl *tbl = d->part_tbl; struct hd_struct **parts = (void *)tbl +
sizeof(struct disk_part_tbl); struct hd_struct **partp = parts + bio->bi_partno;
struct hd_struct *p = *partp; dev_t disk = p->__dev.devt; disk ==
MKDEV(254,16);}) && bio->bi_iter.bi_sector == 128)");
    stub_->FailMMOrBIO(&ctx, req, &resp);
  }

 private:
  std::unique_ptr<bpfki::BPFKIService::Stub> stub_;
  const std::shared_ptr<spdlog::logger>& logger_;
};


int main(int argc, char *argv[]) {
  auto logger = spdlog::stdout_color_mt("console");
  BPFKIClient cli(grpc::CreateChannel(
    "localhost:50051", grpc::InsecureChannelCredentials()),
    logger);
  cli.FailMMOrBIO();
  return 0;
}
