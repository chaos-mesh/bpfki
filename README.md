# bpfki

A BPF-based kernel fault injection service.

# Prerequisites

Kernel with `bpf_override_return` and  `should_fail_page_alloc`,
`should_fail_slab`, `should_fail_bio` for BPF error injection support.


# Building

``` sh
mkdir build && cd build
cmake ../
make -j
```

# Using

`cd bin && nohup ./bpfki &`

# Interface

``` c++
syntax = "proto3";

package bpfki;

message BumpTimeRequest {
  uint32 pid = 1;
  uint32 tid = 2;
  int32 second = 3;
  int32 subsecond = 4;
  float probability = 5;
}

message FailKernRequest {
  uint32 pid = 1;
  uint32 tid = 2;
  enum FAILTYPE {
    SLAB = 0;
    PAGE = 1;
    BIO = 2;
  }
  FAILTYPE ftype = 3;
  repeated string headers = 4;
  message frame {
    string funcname = 1;
    string parameters = 2;
    string predicate = 3;
  }
  repeated frame callchain = 5;
  float probability = 6;
  uint32 times = 7;
}

message StatusResponse {
  int32 ret = 1;
  string msg = 2;
}

service BPFKIService {
  rpc SetTimeVal(BumpTimeRequest) returns (StatusResponse) {}
  rpc RecoverTimeVal(BumpTimeRequest) returns (StatusResponse) {}
  rpc SetTimeSpec(BumpTimeRequest) returns (StatusResponse) {}
  rpc RecoverTimeSpec(BumpTimeRequest) returns (StatusResponse) {}
  rpc FailMMOrBIO(FailKernRequest) returns (StatusResponse) {}
  rpc RecoverMMOrBIO(FailKernRequest) returns (StatusResponse) {}
}
```
