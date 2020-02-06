#include <iostream>

#include <gflags/gflags.h>
#include <grpcpp/grpcpp.h>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include "service.h"

DEFINE_string(host, "0.0.0.0", "Host of BPFKI server");
DEFINE_string(port, "50051", "Port of BPFKI server");
DEFINE_string(loglevel, "info", "Set the logging level "
              "(\"debug\"|\"info\"|\"warn\"|\"error\"|"
              "\"fatal\") (default \"info\")");

int main(int argc, char *argv[]) {
  gflags::ParseCommandLineFlags(&argc, &argv, true);
  std::string addr = FLAGS_host + ":" + FLAGS_port;
  auto logger = spdlog::stdout_color_mt("console");
  logger->set_level(spdlog::level::info);
  bpfki::BPFKIServiceImpl srv(logger);
  grpc::ServerBuilder builder;
  builder.AddListeningPort(addr, grpc::InsecureServerCredentials());
  builder.RegisterService(&srv);
  std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
  logger->info("BPFKI server run on {0}", addr);
  server->Wait();
  return 0;
}
