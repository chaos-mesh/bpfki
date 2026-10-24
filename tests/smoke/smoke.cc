#include <chrono>
#include <iostream>

#include <grpcpp/grpcpp.h>

#include "bpfki.grpc.pb.h"

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cerr << "usage: bpfki-smoke HOST:PORT\n";
    return 1;
  }
  auto channel = grpc::CreateChannel(argv[1], grpc::InsecureChannelCredentials());
  if (!channel->WaitForConnected(std::chrono::system_clock::now() +
                                 std::chrono::seconds(10))) {
    std::cerr << "service did not become ready\n";
    return 1;
  }
  auto stub = bpfki::BPFKIService::NewStub(channel);
  bpfki::FailKernRequest kern_request;
  bpfki::StatusResponse kern_response;
  grpc::ClientContext kern_context;
  kern_context.set_deadline(std::chrono::system_clock::now() +
                            std::chrono::seconds(5));
  auto kern_status = stub->RecoverMMOrBIO(&kern_context, kern_request, &kern_response);
  if (!kern_status.ok() || kern_response.ret() != 0 || !kern_response.msg().empty()) {
    std::cerr << "RecoverMMOrBIO failed: " << kern_status.error_message()
              << " ret=" << kern_response.ret() << " " << kern_response.msg() << "\n";
    return 1;
  }
  bpfki::BumpTimeRequest time_request;
  bpfki::StatusResponse time_response;
  grpc::ClientContext time_context;
  time_context.set_deadline(std::chrono::system_clock::now() +
                            std::chrono::seconds(5));
  auto time_status = stub->RecoverTimeVal(&time_context, time_request, &time_response);
  if (!time_status.ok() || time_response.ret() != 0 || !time_response.msg().empty()) {
    std::cerr << "RecoverTimeVal failed: " << time_status.error_message()
              << " ret=" << time_response.ret() << " " << time_response.msg() << "\n";
    return 1;
  }
  std::cout << "RecoverMMOrBIO and RecoverTimeVal returned OK and ret=0. "
            << "Communication only; no fault was injected.\n";
  return 0;
}
