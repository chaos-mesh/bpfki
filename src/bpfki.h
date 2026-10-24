#pragma once

#include <iostream>
#include <optional>
#include <set>
#include <vector>

#include <ctime>

#include <bcc/BPF.h>
#include <spdlog/spdlog.h>

#include "absl/hash/hash.h"
#include "bio_probe.h"

namespace bpfki {

class BPFKI {
 public:
  BPFKI() {}
  BPFKI(const BPFKI&) = delete;
  BPFKI& operator=(const BPFKI&) = delete;

  virtual int init(void) = 0;
  virtual int update_inject_cond(const void *req, bool clear = false) = 0;
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
  int update_inject_cond(const void *req, bool clear = false);
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
  enum Type : int {
    SLAB,
    PAGE,
    BIO,
  };

  class Frame {
   public:
    Frame(const std::string &funcname,
          const std::string &parameters,
          const std::string &predicate)
      : funcname_(funcname),
        parameters_(parameters),
        predicate_(predicate) {}

    template <typename H>
    friend H AbslHashValue(H h, const Frame& f) {
      return H::combine(std::move(h), f.funcname_,
                        f.parameters_, f.predicate_);
    }

   public:
    inline const std::string& funcname() const {
      return funcname_;
    }
    inline const std::string& parameters() const {
      return parameters_;
    }
    inline const std::string& predicate() const {
      return predicate_;
    }

   private:
    const std::string funcname_;
    const std::string parameters_;
    const std::string predicate_;
  };

  class Probe {
   public:
    Probe(const std::string& event, const std::string& func, bool is_entry)
      : event_(event), func_(func), is_entry_(is_entry) {}

   public:
      inline const std::string& event() const {
        return event_;
      }
      inline const std::string& func() const {
        return func_;
      }
      inline bool is_entry() const {
        return is_entry_;
      }

   private:
    const std::string event_;
    const std::string func_;
    bool is_entry_;
  };

  explicit FailKern(const std::shared_ptr<spdlog::logger>& logger,
                    Type type, std::vector<std::string>& headers,
                    std::vector<Frame>& challchain)
    : logger_(logger),
      bpf_(std::make_unique<ebpf::BPF>()),
      type_(type),
      headers_(headers),
      callchain_(challchain) {}
  int init(void);
  int update_inject_cond(const void *req, bool clear = false);
  ~FailKern() {};
 private:
  friend struct FailKernTestAccess;

  struct GeneratedProgram {
    std::string source;
    size_t stack_slots;
  };
  struct FilterMap {
    int borrowed_fd = -1;
    size_t stack_slots = 0;
  };

  GeneratedProgram gen_bpf_prog(void);
  void bind_filter_map(size_t stack_slots);
  void attach_probes(void);
  std::string gen_prelude(int max_frame_id);
  void gen_func_sig(std::string *func_sig, std::string& event,
                    std::string& params, bool is_entry);
  std::string gen_should_fail(int frame_id);
  std::string gen_entry(std::string& event, std::string& params,
                        std::string& pred, int frame_id,
                        int max_frame_id);
  std::string gen_exit(std::string& event, std::string& params,
                       int max_frame_id);

 private:
  const std::shared_ptr<spdlog::logger>& logger_;
  std::unique_ptr<ebpf::BPF> bpf_;
  const Type type_;
  std::vector<std::string> &headers_;
  std::vector<Frame> &callchain_;
  FilterMap filter_map_;
  std::optional<bio_probe::Identity> bio_probe_;
  std::vector<Probe> probes_;
  std::set<uint32_t> fids_;
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
