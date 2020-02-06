#include <fstream>
#include <map>

#include <absl/strings/str_cat.h>
#include <absl/strings/str_format.h>

#include "bpfki.h"
#include "bpfki.pb.h"

namespace bpfki {

BPFKI::~BPFKI() {
}

int BumpTime::init(void) {
  std::ifstream ifs(prog_name_);
  std::string prog((std::istreambuf_iterator<char>(ifs)),
                      (std::istreambuf_iterator<char>()));
  auto init_res = bpf_->init(prog);
  if(init_res.code() != 0)
    throw std::invalid_argument(init_res.msg());
  logger_->info("Phase 1: load prog");

  std::map<std::string, int> deps = {{"balance", 2}, {"write", 1}};
  for (const auto& dep: deps) {
    auto pt = bpf_->get_prog_table(dep.first);
    int idx = 1, pfd = -1;
    for (int i{0}; i < dep.second; i++) {
      std::string func_name = absl::StrFormat("%s_step%d", dep.first, idx);
      auto loadRes = bpf_->load_func(func_name, BPF_PROG_TYPE_KPROBE, pfd);
      if (loadRes.code() != 0)
        throw std::invalid_argument(loadRes.msg());
      auto updateRes = pt.update_value(idx, pfd);
      if (updateRes.code() != 0)
        throw std::invalid_argument(updateRes.msg());
      idx++;
    }
  }
  logger_->info("Phase 2: resolve dependencies");

  std::string fn_name = "syscall__";
  absl::StrAppend(&fn_name, prog_name_, "_entry");
  auto attach_res = bpf_->attach_kprobe(syscall_fnname_, fn_name, 0,
                                        BPF_PROBE_ENTRY);
  if (attach_res.code() != 0)
    throw std::invalid_argument(attach_res.msg());
  fn_name = "do_ret_sys_";
  absl::StrAppend(&fn_name, prog_name_, "_return");
  attach_res = bpf_->attach_kprobe(syscall_fnname_, fn_name, 0,
                                   BPF_PROBE_RETURN);
  if (attach_res.code() != 0)
    throw std::invalid_argument(attach_res.msg());
  logger_->info("Phase 3: attach time events {}", syscall_fnname_);

  return 0;
}

int BumpTime::update_inject_cond(const void *_req) {
  auto req = reinterpret_cast<const BumpTimeRequest*>(_req);
  auto filter_map = bpf_->get_hash_table
    <uint32_t, BumpTime::clock_filter>("clock_filters");
  BumpTime::clock_filter cf = {
    .sec = req->second(),
    .ssec = req->subsecond(),
    .pct = static_cast<long>((1UL << 32) * req->probability()),
  };
  auto fid = req->pid();
  auto tid = req->tid();
  if (tid != 0 && fid != tid)
    fid = tid;
  if (cf.sec == 0 && cf.ssec == 0) {
    auto remove_res = filter_map.remove_value(fid);
    if (remove_res.code() != 0)
      throw std::invalid_argument(remove_res.msg());
    fids_.erase(fid);
    logger_->info("Recover: task {}'s {}", fid, syscall_fnname_);
  } else {
    auto update_res = filter_map.update_value(fid, cf);
    if (update_res.code() != 0)
      throw std::invalid_argument(update_res.msg());
    fids_.insert(fid);
    logger_->info("Set: task {}'s {} with sec {} ssec {} pct {}",
                  fid, syscall_fnname_, cf.sec, cf.ssec, cf.pct);
  }

  return fids_.size();
}

BumpTime::~BumpTime() {
  logger_->info("Detach {}", syscall_fnname_);
}

};
