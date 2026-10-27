#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <limits>
#include <map>
#include <sys/random.h>

#include <absl/strings/str_cat.h>
#include <absl/strings/str_format.h>
#include <absl/strings/str_split.h>
#include <bcc/libbpf.h>

#include "bpfki.h"
#include "bpfki.pb.h"
#include "filter_layout.h"

namespace bpfki {
namespace {

std::string ProbeNamespace() {
  std::array<unsigned char, 16> bytes;
  size_t offset = 0;
  while (offset < bytes.size()) {
    const auto count = getrandom(bytes.data() + offset, bytes.size() - offset, 0);
    if (count < 0 && errno == EINTR)
      continue;
    if (count <= 0)
      throw std::invalid_argument("cannot read OS entropy for the FailKern probe namespace");
    offset += static_cast<size_t>(count);
  }
  constexpr char hex[] = "0123456789abcdef";
  std::string name;
  name.reserve(bytes.size() * 2);
  for (const auto byte : bytes) {
    name.push_back(hex[byte >> 4]);
    name.push_back(hex[byte & 15]);
  }
  return name;
}

}

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

int BumpTime::update_inject_cond(const void *_req, bool clear) {
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
  if (fid == 0)
      throw std::invalid_argument("tid and pid cannot be 0 at the same time");
  if (clear) {
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

int FailKern::init(void) {
  auto prog = gen_bpf_prog();
  logger_->info("load FailKern prog:\n{}", prog.source);
  auto init_res = bpf_->init(prog.source);
  if (init_res.code() != 0)
    throw std::invalid_argument(init_res.msg());
  bind_filter_map(prog.stack_slots);
  attach_probes();
  return 0;
}

void FailKern::bind_filter_map(size_t stack_slots) {
  const size_t expected_size = filter_layout::ValueSize(stack_slots);
  const int fd = bpf_->get_table("ctxs").get_fd();
  struct bpf_map_info info = {};
  uint32_t info_size = sizeof(info);
  if (bpf_obj_get_info(fd, &info, &info_size) != 0) {
    const int error = errno;
    throw std::invalid_argument(absl::StrCat("read ctxs map metadata: ",
                                            std::strerror(error)));
  }
  if (info_size < offsetof(struct bpf_map_info, value_size) + sizeof(info.value_size) ||
      info.type != BPF_MAP_TYPE_HASH || info.key_size != sizeof(uint32_t) ||
      info.value_size != expected_size)
    throw std::invalid_argument("ctxs map type or layout does not match the filter schema");
  filter_map_ = {fd, stack_slots};
}

int FailKern::update_inject_cond(const void *_req, bool clear) {
  auto req = reinterpret_cast<const FailKernRequest*>(_req);
  auto fid = req->pid();
  auto tid = req->tid();
  if (tid != 0 && fid != tid)
    fid = tid;
  if (fid == 0)
      throw std::invalid_argument("tid and pid cannot be 0 at the same time");
  if (clear) {
    if (bpf_delete_elem(filter_map_.borrowed_fd, &fid) != 0) {
      const int error = errno;
      throw std::invalid_argument(absl::StrCat("delete ctxs filter: ",
                                              std::strerror(error)));
    }
    fids_.erase(fid);
    logger_->info("Recover: task {}'s FailKern", fid);
  } else {
    if (static_cast<int>(type_) != static_cast<int>(req->ftype()))
      throw UnsupportedInjection("fault type differs from the active callchain; recover it before changing type");
    const auto condition = filter_layout::ParseCondition(req->probability(), req->times());
    auto words = filter_layout::InitialWords(filter_map_.stack_slots, condition);
    if (type_ == BIO) {
      if (!bio_probe_)
        throw UnsupportedInjection("BIO unsupported: no verified owned attachment");
      bio_probe::Recheck(*bio_probe_, filter_map_.borrowed_fd);
    }
    if (bpf_update_elem(filter_map_.borrowed_fd, &fid, words.data(), BPF_ANY) != 0) {
      const int error = errno;
      throw std::invalid_argument(absl::StrCat("update ctxs filter: ",
                                              std::strerror(error)));
    }
    fids_.insert(fid);
    logger_->info("Set: task {}'s Failkern with pct {} max_inject_times {}",
                  fid, condition.threshold, condition.limit);
  }
  return fids_.size();
}

std::string FailKern::gen_prelude(int nr_frame) {
  std::string include_header = "#include <linux/mm.h>\n";
  for (auto& header: headers_) {
    absl::StrAppend(&include_header,
                    absl::StrFormat("#include <%s>\n", header));
  }
  auto maps = filter_layout::BpfDeclaration(nr_frame) + R"(
BPF_HASH(ctxs, u32, struct fk_ctx);

static __inline bool accept_probability(struct fk_ctx *fc)
{
    return (u64)bpf_get_prandom_u32() < fc->pct;
}
  )";

  auto strcmp_ = R"(
static __inline bool STRNCMP(const char *s1, const char *s2, int n)
{
    for (int i = 0; i < n; ++i) {
        if (s1[i] != s2[i]) {
            return false;
        }
    }
    return true;
}
  )";

  std::string prelude;
  absl::StrAppend(&prelude, include_header, maps, strcmp_);
  return prelude;
}

void FailKern::gen_func_sig(std::string* func_sig, std::string& event,
                            std::string& params, bool is_entry) {
  auto suffix = "_exit";
  if (is_entry)
    suffix = "_entry";
  if (params == "")
    absl::StrAppend(func_sig, "int ", event, suffix, "(struct pt_regs *ctx)");
  else
    absl::StrAppend(func_sig, "int ", event, suffix,
                    "(struct pt_regs *ctx, ", params, ")");
}

std::string FailKern::gen_should_fail(int nr_frame) {
  std::string pred;
  if (callchain_.size() == 0) {
    pred = "(true)";
  } else {
    auto frame = callchain_.back();
    pred = frame.predicate();
    if (frame.predicate() == "")
      pred = "(true)";
    if (frame.funcname() == "")
      callchain_.pop_back();
  }
  auto frame_id = nr_frame - 1;
  std::string event, func, err_code, params;
  if (type_ == SLAB) {
    event = "should_failslab";
    params = "struct kmem_cache *s, gfp_t gfpflags";
    err_code = "-ENOMEM";
  } else if (type_ == PAGE) {
    event = "should_fail_alloc_page";
    params = "gfp_t gfp_mask, unsigned int order";
    err_code = "true";
  } else if (type_ == BIO) {
    event = "should_fail_bio";
    params = "struct bio *bio";
    err_code = "-EIO";
  }
  absl::StrAppend(&func, event, "_entry");
  probes_.push_back(FailKern::Probe(event, func, true));
  std::string func_sig;
  gen_func_sig(&func_sig, event, params, true);

  auto part1 = absl::StrFormat(R"(
%s
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32, tid = id;
    struct fk_ctx *fc = NULL;

    fc = ctxs.lookup(&tid);
    if (!fc) {
        fc = ctxs.lookup(&pid);
        if (!fc)
            return 0;
    }
)", func_sig);

  auto part2 = R"(
    fc->ignore = !accept_probability(fc);
  )";

  auto part3 = absl::StrFormat(R"(
    if (fc->ignore)
        return 0;

    /*
     * If this is the only call in the chain and predicate passes
     */
    if (%d == 1 && %s && (fc->max_inject_times == 0 ||
                          fc->inject_times < fc->max_inject_times)) {
        fc->inject_times++;
        bpf_override_return(ctx, %s);
        return 0;
    }

    /*
     * If all conds have been met and predicate passes
     */
    if (fc->conds_met == %d && %s && (fc->max_inject_times == 0 ||
                                      fc->inject_times < fc->max_inject_times)) {
        fc->inject_times++;
        bpf_override_return(ctx, %s);
    }
    return 0;
}
  )" , nr_frame, pred, err_code, frame_id, pred, err_code);

  std::string should_fail;
  if (frame_id == 0)
    absl::StrAppend(&should_fail, part1, part2, part3);
  else
    absl::StrAppend(&should_fail, part1, part3);
  return should_fail;
}

std::string FailKern::gen_entry(std::string& event, std::string& params,
                                  std::string& pred, int frame_id,
                                  int nr_frame) {
  std::string func_sig;
  gen_func_sig(&func_sig, event, params, true);
  if (pred == "")
    pred = "(true)";
  auto part1 = absl::StrFormat(R"(
%s
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32, tid = id;
    struct fk_ctx *fc = NULL;

    fc = ctxs.lookup(&tid);
    if (!fc) {
        fc = ctxs.lookup(&pid);
        if (!fc)
            return 0;
    }
  )", func_sig);

  auto part2 = R"(
    fc->ignore = !accept_probability(fc);
  )";

  auto part3 = absl::StrFormat(R"(
    if (fc->ignore)
        return 0;
    if (fc->conds_met >= %d)
        return 0;
    if (fc->conds_met == %d && %s) {
        fc->stack[%d] = fc->curr_call;
        fc->conds_met++;
    }

    fc->curr_call++;
    return 0;
}
  )", nr_frame, frame_id, pred, frame_id);
  std::string entry;
  if (frame_id == 0)
    absl::StrAppend(&entry, part1, part2, part3);
  else
    absl::StrAppend(&entry, part1, part3);
  return entry;
}

std::string FailKern::gen_exit(std::string& event, std::string& params,
                               int max_frame_id) {
  std::string func_sig;
  gen_func_sig(&func_sig, event, params, false);
  return absl::StrFormat(R"(
%s
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32, tid = id;
    struct fk_ctx *fc = NULL;

    fc = ctxs.lookup(&tid);
    if (!fc) {
        fc = ctxs.lookup(&pid);
        if (!fc)
            return 0;
    }
    if (fc->ignore)
        return 0;

    fc->curr_call--;

    if (fc->conds_met < 1 || fc->conds_met >= %d)
        return 0;
    if (fc->stack[fc->conds_met - 1] == fc->curr_call)
        fc->conds_met--;

    return 0;
}
  )", func_sig, max_frame_id + 1);
}

FailKern::GeneratedProgram FailKern::gen_bpf_prog(void) {
  auto size = callchain_.size();
  if (size >= static_cast<size_t>(std::numeric_limits<int>::max() - 1))
    throw std::invalid_argument("too many callchain frames");
  const auto stack_slots = size == 1 && callchain_.back().funcname() == "" ? 1 : size + 1;
  filter_layout::ValueSize(stack_slots);
  auto nr_frame = static_cast<int>(stack_slots);
  auto prelude = gen_prelude(nr_frame);
  auto should_fail = gen_should_fail(nr_frame);
  std::string prog;
  absl::StrAppend(&prog, prelude, should_fail);
  if (nr_frame == 1)
    return {std::move(prog), stack_slots};
  auto frame_id = nr_frame - 2;
  for (auto it = callchain_.rbegin(); it != callchain_.rend(); it++) {
    auto event = it->funcname();
    auto params = it->parameters();
    auto pred = it->predicate();
    auto entry = gen_entry(event, params, pred, frame_id--, nr_frame);
    auto exit = gen_exit(event, params, nr_frame);
    absl::StrAppend(&prog, entry, exit);

    std::string entry_func, exit_func;
    absl::StrAppend(&entry_func, event, "_entry");
    probes_.push_back(FailKern::Probe(event, entry_func, true));
    absl::StrAppend(&exit_func, event, "_exit");
    probes_.push_back(FailKern::Probe(event, exit_func, false));
  }
  return {std::move(prog), stack_slots};
}

void FailKern::attach_probes(void) {
  if (!attachments_.empty())
    throw std::invalid_argument("FailKern probe attachment was already initialized");
  const auto probe_namespace = ProbeNamespace();
  attachments_.reserve(probes_.size());
  for (size_t i = 0; i < probes_.size(); ++i)
    attachments_.push_back({absl::StrCat("bpfki_", probe_namespace, "_", i)});

  for (size_t i = 0; i < probes_.size(); ++i) {
    const auto& probe = probes_[i];
    auto& attachment = attachments_[i];
    auto type = BPF_PROBE_ENTRY;
    if (!probe.is_entry())
      type = BPF_PROBE_RETURN;
    int program_fd = -1;
    auto load_res = bpf_->load_func(probe.func(), BPF_PROG_TYPE_KPROBE, program_fd);
    if (load_res.code() != 0)
      throw std::invalid_argument(load_res.msg());
    const bool bio_entry = type_ == BIO && probe.is_entry() &&
                           probe.event() == "should_fail_bio";
    attachment.attempted = true;
    attachment.perf_fd = bpf_attach_kprobe(program_fd, type, attachment.event_name.c_str(),
                                          probe.event().c_str(), 0, 0);
    if (attachment.perf_fd < 0) {
      const int error = errno;
      throw std::invalid_argument(absl::StrCat("attach FailKern probe ", probe.event(),
                                              " as ", attachment.event_name, ": ",
                                              std::strerror(error)));
    }
    if (bio_entry)
      bio_probe_ = bio_probe::Capture(attachment.perf_fd, program_fd, filter_map_.borrowed_fd);
  }
}

FailKern::~FailKern() noexcept {
  const auto report = [this](const char* operation, const Attachment& attachment,
                             int error) noexcept {
    try {
      logger_->error("FailKern {} failed for {} (errno {})", operation,
                     attachment.event_name, error);
    } catch (...) {
      std::fprintf(stderr, "FailKern %s failed for %s (errno %d)\n", operation,
                   attachment.event_name.c_str(), error);
    }
  };
  for (auto& attachment : attachments_) {
    if (attachment.perf_fd >= 0) {
      const int fd = attachment.perf_fd;
      attachment.perf_fd = -1;
      if (bpf_close_perf_event_fd(fd) != 0)
        report("perf FD close", attachment, errno);
    }
    if (attachment.attempted) {
      attachment.attempted = false;
      if (bpf_detach_kprobe(attachment.event_name.c_str()) != 0)
        report("tracefs event removal", attachment, errno);
    }
  }
}

};
