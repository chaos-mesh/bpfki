#include "bio_probe.h"

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace bpfki {
namespace bio_probe {
namespace {

[[noreturn]] void Reject(const std::string& reason) {
  throw UnsupportedInjection("BIO unsupported: " + reason);
}

void Info(int fd, void* info, uint32_t& size) {
  union bpf_attr attr{};
  attr.info.bpf_fd = fd;
  attr.info.info_len = size;
  attr.info.info = reinterpret_cast<uintptr_t>(info);
  if (syscall(SYS_bpf, BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) != 0)
    Reject("cannot read owned BPF object metadata: " + std::string(std::strerror(errno)));
  size = attr.info.info_len;
}

Program ReadProgram(int fd) {
  struct bpf_prog_info info{};
  uint32_t size = sizeof(info);
  Info(fd, &info, size);
  if (size < offsetof(struct bpf_prog_info, map_ids) + sizeof(info.map_ids) ||
      info.type != BPF_PROG_TYPE_KPROBE || info.id == 0 ||
      info.nr_map_ids == 0 || info.nr_map_ids > 4096)
    Reject("missing, incomplete, or oversized owned program metadata");
  const auto id = info.id;
  std::vector<uint32_t> maps(info.nr_map_ids);
  info = {};
  info.nr_map_ids = maps.size();
  info.map_ids = reinterpret_cast<uintptr_t>(maps.data());
  size = sizeof(info);
  Info(fd, &info, size);
  if (size < offsetof(struct bpf_prog_info, map_ids) + sizeof(info.map_ids) ||
      info.type != BPF_PROG_TYPE_KPROBE || info.id != id || info.nr_map_ids != maps.size())
    Reject("owned program metadata changed or was truncated");
  return {id, std::move(maps)};
}

uint32_t ReadMap(int fd) {
  struct bpf_map_info info{};
  uint32_t size = sizeof(info);
  Info(fd, &info, size);
  if (size < offsetof(struct bpf_map_info, id) + sizeof(info.id) ||
      info.id == 0 || info.type != BPF_MAP_TYPE_HASH)
    Reject("missing or incomplete owned ctxs map metadata");
  return info.id;
}

Query ReadQuery(int fd) {
  std::array<char, 256> symbol{};
  union bpf_attr attr{};
  attr.task_fd_query.pid = getpid();
  attr.task_fd_query.fd = fd;
  attr.task_fd_query.buf_len = symbol.size();
  attr.task_fd_query.buf = reinterpret_cast<uintptr_t>(symbol.data());
  if (syscall(SYS_bpf, BPF_TASK_FD_QUERY, &attr, sizeof(attr)) != 0)
    Reject("cannot query owned perf FD: " + std::string(std::strerror(errno)));
  const size_t length = attr.task_fd_query.buf_len;
  if (length >= symbol.size() || strnlen(symbol.data(), symbol.size()) != length)
    Reject("incomplete owned perf FD symbol");
  return {attr.task_fd_query.prog_id,
          attr.task_fd_query.fd_type == BPF_FD_TYPE_KPROBE,
          std::string(symbol.data(), length), attr.task_fd_query.probe_offset,
          attr.task_fd_query.probe_addr};
}

std::string ReadListing() {
  constexpr size_t limit = 1024 * 1024;
  std::ifstream input("/sys/kernel/debug/kprobes/list");
  if (!input.is_open())
    Reject("cannot read /sys/kernel/debug/kprobes/list");
  std::string listing(limit + 1, '\0');
  input.read(listing.data(), listing.size());
  listing.resize(input.gcount());
  if (input.bad() || !input.eof() || listing.size() > limit)
    Reject("unreadable, incomplete, or oversized /sys/kernel/debug/kprobes/list");
  return listing;
}

}

std::set<int> SelfPerfFds() {
  std::set<int> fds;
  try {
    size_t count = 0;
    for (const auto& entry : std::filesystem::directory_iterator("/proc/self/fd")) {
      if (++count > 4096)
        Reject("self FD inventory exceeds 4096 entries");
      if (std::filesystem::read_symlink(entry.path()) == "anon_inode:[perf_event]")
        fds.insert(std::stoi(entry.path().filename().string()));
    }
  } catch (const std::filesystem::filesystem_error& error) {
    Reject("cannot inventory self perf FDs: " + std::string(error.what()));
  }
  return fds;
}

Identity Capture(const std::set<int>& before, int program_fd, int map_fd) {
  const auto after = SelfPerfFds();
  std::vector<std::pair<int, Query>> added;
  for (int fd : after) {
    if (before.count(fd) == 0)
      added.emplace_back(fd, ReadQuery(fd));
  }
  const auto program = ReadProgram(program_fd);
  const auto identity = Select(program_fd, program, ReadMap(map_fd), added);
  Recheck(identity, map_fd);
  return identity;
}

void Recheck(const Identity& identity, int map_fd) {
  const auto before = ReadQuery(identity.borrowed_perf_fd);
  const auto program = ReadProgram(identity.borrowed_program_fd);
  const auto map_id = ReadMap(map_fd);
  RequireIdentity(identity, program, map_id, before);
  const auto listing = ReadListing();
  const auto after = ReadQuery(identity.borrowed_perf_fd);
  RequireIdentity(identity, program, map_id, after);
  RequireFtrace(listing, identity.address);
}

}
}
