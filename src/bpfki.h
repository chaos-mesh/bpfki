#pragma once

#include <iostream>
#include <set>
#include <ctime>

#include <bcc/BPF.h>
#include <spdlog/spdlog.h>

namespace bpfki {

class BPFKI {
 public:
  BPFKI() {}
  BPFKI(const BPFKI&) = delete;
  BPFKI& operator=(const BPFKI&) = delete;

  virtual int init(void) = 0;
  virtual int update_inject_cond(const void *req) = 0;
  virtual ~BPFKI();
};

class BumpTime : public BPFKI {
 public:
  struct clock_filter {
    long sec;
    union {
      long ssec;
      long nsec;
      long usec;
    };
    long pct;
    union {
      struct timespec *ts;
      struct timeval *tv;
    };
    union {
      struct timespec nts;
      struct timeval ntv;
    };
  };

 public:
  BumpTime(const std::shared_ptr<spdlog::logger>& logger,
           const std::string& prog_name)
    : logger_(logger),
      bpf_(std::make_unique<ebpf::BPF>()),
      prog_name_(prog_name),
      syscall_fnname_(bpf_->get_syscall_fnname(prog_name)) {}
  int init(void);
  int update_inject_cond(const void *req);
  ~BumpTime();

 private:
  const std::shared_ptr<spdlog::logger>& logger_;
  std::unique_ptr<ebpf::BPF> bpf_;
  const std::string& prog_name_;
  const std::string syscall_fnname_;
  std::set<uint32_t> fids_;
};

class FailKern : public BPFKI {
 public:
  explicit FailKern(const std::shared_ptr<spdlog::logger>& logger)
    : logger_(logger), bpf_(std::make_unique<ebpf::BPF>()) {}
  ~FailKern();
 private:
  const std::shared_ptr<spdlog::logger>& logger_;
  std::unique_ptr<ebpf::BPF> bpf_;
};

class FailSyscall : public BPFKI {
 public:
  FailSyscall();
  ~FailSyscall();
};

template <typename Concrete, typename... Ts>
std::enable_if_t<std::is_constructible<Concrete, Ts&...>::value,
                 std::unique_ptr<Concrete>>
construct(Ts&... params) {
  return std::make_unique<Concrete>(std::forward<Ts>(params)...);
}

template <typename Concrete, typename... Ts>
std::unique_ptr<Concrete> construct(...) {
  return nullptr;
}

template <typename... Ts>
static std::unique_ptr<BPFKI>
createBPFKI(const std::string& name, Ts&... params) {
  if (name == "BumpTime")
    return construct<BumpTime, Ts&...>(std::forward<Ts&>(params)...);
  else if (name == "FailKern")
    return construct<FailKern, Ts&...>(std::forward<Ts&>(params)...);
  else if (name == "FailSyscall")
    return construct<FailSyscall, Ts&...>(std::forward<Ts&>(params)...);

  return nullptr;
}

};
