#include <grpcpp/grpcpp.h>
#include "bpfki.grpc.pb.h"

#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>

#include <fcntl.h>
#include <grp.h>
#include <linux/loop.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <unistd.h>

namespace {
using Clock = std::chrono::steady_clock;
namespace fs = std::filesystem;
constexpr size_t kBytes = 4096;
constexpr unsigned kOperations = 16;
volatile sig_atomic_t interrupted = 0;
void OnSignal(int) { interrupted = 1; }
void Require(bool condition, const std::string& message) {
  if (!condition) throw std::runtime_error(message);
}
std::string Quote(const std::string& value) {
  std::ostringstream out;
  out << '"';
  for (unsigned char c : value) {
    if (c == '\\' || c == '"') out << '\\' << c;
    else if (c < 32) {
      const char* digits = "0123456789abcdef";
      out << "\\u00" << digits[c >> 4] << digits[c & 15];
    } else out << c;
  }
  out << '"';
  return out.str();
}
uint64_t StartTime(pid_t pid) {
  std::ifstream input("/proc/" + std::to_string(pid) + "/stat");
  std::string line, field;
  std::getline(input, line);
  auto end = line.rfind(')');
  Require(end != std::string::npos, "owned process has no /proc identity");
  std::istringstream fields(line.substr(end + 2));
  for (int number = 3; number <= 22; ++number) {
    Require(bool(fields >> field), "short /proc identity");
  }
  return std::stoull(field);
}
int Pidfd(pid_t pid) {
  int fd = syscall(SYS_pidfd_open, pid, 0);
  Require(fd >= 0, "pidfd_open is required");
  return fd;
}
void SignalFd(int fd, int signal) {
  if (fd >= 0) syscall(SYS_pidfd_send_signal, fd, signal, nullptr, 0);
}
bool Exited(int fd, int timeout_ms = 0) {
  pollfd item{fd, POLLIN, 0};
  return poll(&item, 1, timeout_ms) > 0 && (item.revents & POLLIN);
}
struct CleanupFailure : std::runtime_error { using std::runtime_error::runtime_error; };
struct Child {
  pid_t pid = -1;
  int fd = -1;
  uint64_t start = 0;
  void Adopt(pid_t spawned) {
    Require(spawned > 0, "fork failed");
    pid = spawned;
    fd = Pidfd(pid);
    start = StartTime(pid);
  }
  void Check() const {
    Require(fd >= 0 && !Exited(fd) && StartTime(pid) == start,
            "owned process died or changed identity");
  }
  bool Stop() {
    if (pid < 0) return true;
    if (fd >= 0) SignalFd(fd, SIGKILL);
    else kill(pid, SIGKILL);
    bool stopped = fd < 0 || Exited(fd, 2000);
    if (!stopped) return false;
    while (waitpid(pid, nullptr, 0) < 0 && errno == EINTR) {}
    if (fd >= 0) close(fd);
    fd = -1;
    pid = -1;
    return stopped;
  }
  ~Child() { Stop(); }
};

enum class Fault : uint32_t { Slab, Page, Bio };
const char* Name(Fault fault) {
  switch (fault) {
    case Fault::Slab: return "SLAB";
    case Fault::Page: return "PAGE";
    case Fault::Bio: return "BIO";
  }
  return "invalid";
}
struct Result {
  int result = 0;
  int error = 0;
  uint64_t bytes = 0;
};
struct Shared {
  std::atomic<uint32_t> requested{0};
  std::atomic<uint32_t> completed{0};
  std::atomic<uint32_t> ready{0};
  Fault fault = Fault::Slab;
  Result result;
};
static_assert(std::atomic<uint32_t>::is_always_lock_free);

int Worker() {
  if (getuid() == 0 || geteuid() == 0) return 90;
  struct stat state{};
  if (fstat(3, &state) || state.st_size != sizeof(Shared)) return 91;
  auto* shared = static_cast<Shared*>(mmap(nullptr, sizeof(Shared),
      PROT_READ | PROT_WRITE, MAP_SHARED, 3, 0));
  if (shared == MAP_FAILED) return 92;
  alignas(4096) std::array<char, kBytes> buffer{};
  std::array<std::array<int, 2>, kOperations> pipes{};
  if (shared->fault == Fault::Page) {
    for (auto& pipe : pipes) {
      if (pipe2(pipe.data(), O_CLOEXEC | O_NONBLOCK)) return 93;
    }
  }
  if (shared->fault == Fault::Bio) {
    int flags = fcntl(4, F_GETFL);
    if (flags < 0 || (flags & O_ACCMODE) != O_RDONLY || !(flags & O_DIRECT)) return 94;
  }
  for (auto& byte : buffer) byte = 1;
  shared->result = {};
  shared->ready.store(1, std::memory_order_release);
  uint32_t sequence = 0;
  unsigned operation = 0;
  while (operation < kOperations) {
    auto next = shared->requested.load(std::memory_order_acquire);
    if (next == sequence) {
      timespec pause{0, 1000000};
      nanosleep(&pause, nullptr);
      continue;
    }
    if (next != sequence + 1) return 95;
    Result result;
    errno = 0;
    if (shared->fault == Fault::Slab) {
      int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
      result.result = fd < 0 ? -1 : 0;
      result.error = fd < 0 ? errno : 0;
      if (fd >= 0) close(fd);
    } else if (shared->fault == Fault::Page) {
      auto& pipe = pipes[operation];
      ssize_t count = write(pipe[1], buffer.data(), buffer.size());
      result.result = count < 0 ? -1 : 0;
      result.error = count < 0 ? errno : 0;
      result.bytes = count < 0 ? 0 : static_cast<uint64_t>(count);
      close(pipe[0]);
      close(pipe[1]);
    } else if (shared->fault == Fault::Bio) {
      ssize_t count = pread(4, buffer.data(), buffer.size(), operation * kBytes);
      result.result = count < 0 ? -1 : 0;
      result.error = count < 0 ? errno : 0;
      result.bytes = count < 0 ? 0 : static_cast<uint64_t>(count);
    } else return 96;
    shared->result = result;
    sequence = next;
    shared->completed.store(sequence, std::memory_order_release);
    ++operation;
  }
  return 97;
}

struct WorkerProcess {
  Child child;
  int memory_fd = -1;
  Shared* shared = nullptr;
  uint32_t sequence = 0;
  void Start(Fault fault, int disk_fd, uid_t uid, gid_t gid) {
    memory_fd = syscall(SYS_memfd_create, "bpfki-owned-worker", 0);
    Require(memory_fd >= 0 && ftruncate(memory_fd, sizeof(Shared)) == 0,
            "cannot allocate worker shared memory");
    void* mapping = mmap(nullptr, sizeof(Shared), PROT_READ | PROT_WRITE,
                         MAP_SHARED, memory_fd, 0);
    Require(mapping != MAP_FAILED, "cannot map worker shared memory");
    shared = new (mapping) Shared;
    shared->fault = fault;
    int shared_copy = fcntl(memory_fd, F_DUPFD_CLOEXEC, 10);
    int disk_copy = fcntl(disk_fd, F_DUPFD_CLOEXEC, 10);
    if (shared_copy < 0 || disk_copy < 0) {
      if (shared_copy >= 0) close(shared_copy);
      if (disk_copy >= 0) close(disk_copy);
      throw std::runtime_error("cannot duplicate worker descriptors");
    }
    pid_t parent = getpid();
    pid_t pid = fork();
    if (pid == 0) {
      if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent ||
          dup2(shared_copy, 3) < 0 || dup2(disk_copy, 4) < 0 ||
          syscall(SYS_close_range, 5, ~0U, 0) || setgroups(0, nullptr) ||
          setgid(gid) || setuid(uid) || prctl(PR_SET_PDEATHSIG, SIGKILL) ||
          getppid() != parent || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) _exit(98);
      execl("/proc/self/exe", "kernel-tests", "--worker", nullptr);
      _exit(99);
    }
    close(shared_copy);
    close(disk_copy);
    child.Adopt(pid);
    auto deadline = Clock::now() + std::chrono::seconds(3);
    while (!shared->ready.load(std::memory_order_acquire)) {
      child.Check();
      Require(!interrupted && Clock::now() < deadline, "worker readiness timeout");
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
  }
  Result Operate() {
    child.Check();
    shared->requested.store(++sequence, std::memory_order_release);
    auto deadline = Clock::now() + std::chrono::seconds(3);
    while (shared->completed.load(std::memory_order_acquire) != sequence) {
      child.Check();
      Require(!interrupted && Clock::now() < deadline, "worker operation timeout");
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    child.Check();
    return shared->result;
  }
  ~WorkerProcess() {
    child.Stop();
    if (shared) munmap(shared, sizeof(Shared));
    if (memory_fd >= 0) close(memory_fd);
  }
};

struct Disk {
  int file = -1;
  int loop = -1;
  std::string backing;
  std::string device;
  struct stat backing_stat{};
  struct stat device_stat{};
  bool attached = false;
  void Create(const fs::path& directory) {
    backing = (directory / "disk.sparse").string();
    file = open(backing.c_str(), O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
    Require(file >= 0 && ftruncate(file, 8 * 1024 * 1024) == 0 &&
            fstat(file, &backing_stat) == 0, "cannot create private sparse disk");
    int control = open("/dev/loop-control", O_RDWR | O_CLOEXEC);
    Require(control >= 0, "loop-control unavailable");
    int number = ioctl(control, LOOP_CTL_GET_FREE);
    close(control);
    Require(number >= 0, "no unused loop device");
    device = "/dev/loop" + std::to_string(number);
    loop = open(device.c_str(), O_RDONLY | O_DIRECT | O_CLOEXEC | O_NOFOLLOW);
    Require(loop >= 0 && fstat(loop, &device_stat) == 0 &&
            S_ISBLK(device_stat.st_mode) && major(device_stat.st_rdev) == 7 &&
            minor(device_stat.st_rdev) == static_cast<unsigned>(number),
            "acquired device is not a loop block device");
    loop_config config{};
    config.fd = file;
    config.block_size = kBytes;
    config.info.lo_flags = LO_FLAGS_READ_ONLY | LO_FLAGS_AUTOCLEAR;
    Require(ioctl(loop, LOOP_CONFIGURE, &config) == 0, "cannot attach owned loop disk");
    attached = true;
    Check();
  }
  void Check() const {
    loop_info64 info{};
    Require(attached && ioctl(loop, LOOP_GET_STATUS64, &info) == 0 &&
            info.lo_inode == backing_stat.st_ino && info.lo_device == backing_stat.st_dev &&
            (info.lo_flags & LO_FLAGS_READ_ONLY), "loop ownership or read-only state changed");
  }
  uint64_t ReadCompletions() const {
    std::ifstream stats("/sys/dev/block/" + std::to_string(major(device_stat.st_rdev)) +
                        ":" + std::to_string(minor(device_stat.st_rdev)) + "/stat");
    uint64_t count = 0;
    Require(bool(stats >> count), "loop read statistics unavailable");
    return count;
  }
  bool Cleanup() {
    bool clean = true;
    if (attached) {
      loop_info64 info{};
      clean = ioctl(loop, LOOP_GET_STATUS64, &info) == 0 &&
              info.lo_inode == backing_stat.st_ino && info.lo_device == backing_stat.st_dev;
      if (clean) clean = ioctl(loop, LOOP_CLR_FD) == 0;
      attached = false;
    }
    if (loop >= 0) {
      close(loop);
      loop = -1;
      if (!device.empty()) {
        int check = open(device.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        loop_info64 remaining{};
        if (check < 0) clean = false;
        else {
          int result = ioctl(check, LOOP_GET_STATUS64, &remaining);
          if (result == 0 && remaining.lo_inode == backing_stat.st_ino &&
              remaining.lo_device == backing_stat.st_dev) clean = false;
          if (result < 0 && errno != ENXIO) clean = false;
          close(check);
        }
      }
    }
    if (file >= 0) { close(file); file = -1; }
    if (!backing.empty()) {
      struct stat current{};
      if (lstat(backing.c_str(), &current) == 0) {
        bool owned = current.st_dev == backing_stat.st_dev && current.st_ino == backing_stat.st_ino;
        if (owned) clean = unlink(backing.c_str()) == 0 && clean;
        else clean = false;
      } else if (errno != ENOENT) clean = false;
      backing.clear();
    }
    return clean;
  }
  ~Disk() { Cleanup(); }
};

struct Watchdog {
  Child child;
  int done = -1;
  void Start(const Child& service, const Child& target, const Child& control,
             Disk& disk, const fs::path& log) {
    done = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    Require(done >= 0, "watchdog eventfd unavailable");
    int parent = Pidfd(getpid());
    int output = open(log.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
    Require(output >= 0, "cannot create watchdog log");
    pid_t pid = fork();
    if (pid == 0) {
      pollfd watched[2]{{done, POLLIN, 0}, {parent, POLLIN, 0}};
      int ret;
      do { ret = poll(watched, 2, 75000); } while (ret < 0 && errno == EINTR);
      if (ret > 0 && (watched[0].revents & POLLIN)) _exit(0);
      SignalFd(service.fd, SIGKILL);
      pollfd dead{service.fd, POLLIN, 0};
      poll(&dead, 1, 2000);
      SignalFd(target.fd, SIGKILL);
      SignalFd(control.fd, SIGKILL);
      SignalFd(parent, SIGTERM);
      if (!Exited(parent, 3000)) SignalFd(parent, SIGKILL);
      if (Exited(parent, 2000) && Exited(service.fd, 0) &&
          Exited(target.fd, 2000) && Exited(control.fd, 2000)) {
        const char* result = disk.Cleanup() ? "watchdog disk cleanup passed\n"
                                           : "watchdog disk cleanup failed\n";
        ssize_t ignored = write(output, result, strlen(result));
        (void)ignored;
      }
      _exit(100);
    }
    close(output);
    close(parent);
    child.Adopt(pid);
  }
  bool Stop() {
    if (done >= 0) {
      uint64_t finish = 1;
      ssize_t ignored = write(done, &finish, sizeof(finish));
      (void)ignored;
      close(done);
      done = -1;
    }
    return child.Stop();
  }
  ~Watchdog() { Stop(); }
};

struct Session {
  WorkerProcess target;
  WorkerProcess control;
  Child service;
  Watchdog watchdog;
  bool Cleanup() {
    bool ok = service.Stop();
    ok = target.child.Stop() && ok;
    ok = control.child.Stop() && ok;
    return watchdog.Stop() && ok;
  }
  ~Session() { Cleanup(); }
};

unsigned FreePort() {
  int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  Require(fd >= 0, "socket unavailable");
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = 0;
  socklen_t size = sizeof(address);
  int result = bind(fd, reinterpret_cast<sockaddr*>(&address), size);
  if (!result) result = getsockname(fd, reinterpret_cast<sockaddr*>(&address), &size);
  close(fd);
  Require(result == 0, "cannot reserve loopback service port");
  return ntohs(address.sin_port);
}
void CheckListener(const Child& service, unsigned port) {
  service.Check();
  for (const char* table : {"/proc/net/tcp", "/proc/net/tcp6"}) {
    std::ifstream sockets(table);
    std::string line;
    std::getline(sockets, line);
    while (std::getline(sockets, line)) {
      std::istringstream fields(line);
      std::array<std::string, 10> column;
      for (auto& item : column) fields >> item;
      auto separator = column[1].rfind(':');
      if (separator == std::string::npos || column[3] != "0A" ||
          std::stoul(column[1].substr(separator + 1), nullptr, 16) != port) continue;
      auto inode = "socket:[" + column[9] + "]";
      for (const auto& entry : fs::directory_iterator("/proc/" + std::to_string(service.pid) + "/fd")) {
        std::error_code error;
        if (fs::read_symlink(entry.path(), error) == inode && !error) return;
      }
    }
  }
  throw std::runtime_error("RPC listener is not owned by the spawned service");
}
void StartService(Child& child, const fs::path& prefix, const fs::path& log, unsigned port) {
  std::string directory = (prefix / "bin").string();
  std::string executable = (prefix / "bin/bpfki").string();
  std::string port_argument = "--port=" + std::to_string(port);
  int output = open(log.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
  Require(output >= 0, "cannot create service log");
  pid_t parent = getpid();
  pid_t pid = fork();
  if (pid == 0) {
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent ||
        dup2(output, STDOUT_FILENO) < 0 || dup2(output, STDERR_FILENO) < 0 ||
        syscall(SYS_close_range, 3, ~0U, 0) || chdir(directory.c_str())) _exit(101);
    execl(executable.c_str(), executable.c_str(), "--host=127.0.0.1", port_argument.c_str(), nullptr);
    _exit(102);
  }
  close(output);
  child.Adopt(pid);
}

bpfki::FailKernRequest Request(Fault fault, const Child& target, const Disk& disk) {
  target.Check();
  bpfki::FailKernRequest request;
  request.set_pid(target.pid);
  request.set_ftype(static_cast<bpfki::FailKernRequest_FAILTYPE>(fault));
  request.set_probability(1.0f);
  request.set_times(0);
  auto* frame = request.add_callchain();
  if (fault == Fault::Bio) {
    disk.Check();
    request.add_headers("linux/bio.h");
    request.add_headers("linux/blkdev.h");
    request.add_headers("linux/kdev_t.h");
    frame->set_predicate("bio->bi_bdev->bd_dev == MKDEV(" +
        std::to_string(major(disk.device_stat.st_rdev)) + "," +
        std::to_string(minor(disk.device_stat.st_rdev)) + ")");
  } else frame->set_predicate("true");
  return request;
}

struct Progress {
  bool communication = false;
  unsigned loaded = 0;
  unsigned faults = 0;
  unsigned controls = 0;
  unsigned recoveries = 0;
  bool cleanup = false;
};
void RunCase(Fault fault, const fs::path& prefix, const std::string& label,
             const fs::path& output, Disk& disk, uid_t uid, gid_t gid, std::ofstream& events,
             Progress& progress) {
  Session session;
  const std::string case_id = label + "-" + Name(fault);
  bool cleanup_ok = false;
  try {
    session.target.Start(fault, disk.loop, uid, gid);
    session.control.Start(fault, disk.loop, uid, gid);
    unsigned port = FreePort();
    StartService(session.service, prefix, output / (case_id + ".log"), port);
    session.watchdog.Start(session.service, session.target.child, session.control.child,
                           disk, output / (case_id + "-watchdog.log"));
    auto channel = grpc::CreateChannel("127.0.0.1:" + std::to_string(port),
                                       grpc::InsecureChannelCredentials());
    Require(channel->WaitForConnected(std::chrono::system_clock::now() + std::chrono::seconds(10)),
            "service readiness timeout");
    CheckListener(session.service, port);
    progress.communication = true;
    auto stub = bpfki::BPFKIService::NewStub(channel);
    auto request = Request(fault, session.target.child, disk);
    auto record = [&](const std::string& stage, unsigned cycle, WorkerProcess& worker,
                      bool failure) {
      session.service.Check();
      session.target.child.Check();
      session.control.child.Check();
      uint64_t reads_before = fault == Fault::Bio ? disk.ReadCompletions() : 0;
      Result result = worker.Operate();
      uint64_t reads_after = fault == Fault::Bio ? disk.ReadCompletions() : 0;
      int expected = fault == Fault::Bio ? EIO : ENOMEM;
      bool passed = failure ? result.result == -1 && result.error == expected
                            : result.result == 0 && result.error == 0 &&
                              (fault == Fault::Slab || result.bytes == kBytes) &&
                              (fault != Fault::Bio || reads_after > reads_before);
      events << "{\"installation\":" << Quote(label) << ",\"fault\":" << Quote(Name(fault))
             << ",\"stage\":" << Quote(stage) << ",\"cycle\":" << cycle
             << ",\"pid\":" << worker.child.pid << ",\"starttime\":" << worker.child.start
             << ",\"uid\":" << uid << ",\"sequence\":" << worker.sequence
             << ",\"result\":" << result.result << ",\"errno\":" << result.error
             << ",\"read_ios_before\":" << reads_before << ",\"read_ios_after\":" << reads_after
             << ",\"bytes\":" << result.bytes << ",\"expected_errno\":" << (failure ? expected : 0)
             << ",\"passed\":" << (passed ? "true" : "false") << "}\n" << std::flush;
      Require(passed, case_id + " failed at " + stage);
      if (failure) ++progress.faults;
      if (stage == "control") ++progress.controls;
      if (stage == "recovered") ++progress.recoveries;
    };
    auto rpc = [&](bool recover, unsigned cycle) {
      Require(!interrupted, "interrupted before RPC");
      session.service.Check();
      session.target.child.Check();
      session.control.child.Check();
      grpc::ClientContext context;
      context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(10));
      bpfki::StatusResponse response;
      auto status = recover ? stub->RecoverMMOrBIO(&context, request, &response)
                            : stub->FailMMOrBIO(&context, request, &response);
      events << "{\"installation\":" << Quote(label) << ",\"fault\":" << Quote(Name(fault))
             << ",\"stage\":" << Quote(recover ? "recover_rpc" : "inject_rpc")
             << ",\"cycle\":" << cycle << ",\"pid\":" << session.target.child.pid
             << ",\"starttime\":" << session.target.child.start
             << ",\"grpc_code\":" << static_cast<int>(status.error_code())
             << ",\"response_ret\":" << response.ret()
             << ",\"message\":" << Quote(status.error_message() + response.msg())
             << ",\"request\":" << Quote(request.DebugString()) << "}\n" << std::flush;
      Require(status.ok() && response.ret() == 0, case_id + " RPC failed");
      if (!recover) ++progress.loaded;
    };
    record("baseline_target", 0, session.target, false);
    record("baseline_control", 0, session.control, false);
    for (unsigned cycle = 1; cycle <= 2; ++cycle) {
      rpc(false, cycle);
      record("injected", cycle, session.target, true);
      record("control", cycle, session.control, false);
      record("pre_recovery", cycle, session.target, true);
      rpc(true, cycle);
      record("recovered", cycle, session.target, false);
      record("recovered_control", cycle, session.control, false);
    }
    cleanup_ok = progress.cleanup = session.Cleanup();
    if (!cleanup_ok) throw CleanupFailure(case_id + " process cleanup failed");
  } catch (...) {
    cleanup_ok = progress.cleanup = session.Cleanup();
    events << "{\"installation\":" << Quote(label) << ",\"fault\":" << Quote(Name(fault))
           << ",\"stage\":\"process_cleanup\",\"passed\":"
           << (cleanup_ok ? "true" : "false") << "}\n" << std::flush;
    if (!cleanup_ok) throw CleanupFailure(case_id + " process cleanup failed");
    throw;
  }
  events << "{\"installation\":" << Quote(label) << ",\"fault\":" << Quote(Name(fault))
         << ",\"stage\":\"process_cleanup\",\"passed\":true}\n" << std::flush;
}

std::string Environment(const char* name) {
  const char* value = getenv(name);
  Require(value != nullptr && *value, std::string("missing ") + name);
  return value;
}
void Guard(const fs::path& output, uid_t uid) {
  Require(geteuid() == 0 && uid != 0 && Environment("GITHUB_ACTIONS") == "true" &&
          Environment("RUNNER_ENVIRONMENT") == "github-hosted" &&
          Environment("RUNNER_OS") == "Linux", "requires a disposable GitHub-hosted Linux runner");
  fs::path runner = fs::canonical(Environment("RUNNER_TEMP"));
  Require(runner == "/home/runner/work/_temp" && fs::canonical(output.parent_path()) == runner &&
          output.filename().string().rfind("bpfki-kernel-", 0) == 0,
          "output must be a fresh owned directory directly under RUNNER_TEMP");
  struct stat state{};
  Require(lstat(output.c_str(), &state) == 0 && S_ISDIR(state.st_mode) &&
          state.st_uid == uid && (state.st_mode & 0777) == 0700,
          "output ownership or permissions are invalid");
  struct utsname kernel{};
  Require(uname(&kernel) == 0, "cannot inspect running kernel");
  auto marker = output / "qualified-kernel";
  Require(lstat(marker.c_str(), &state) == 0 && S_ISREG(state.st_mode) && state.st_uid == 0,
          "run the capability probe first");
  std::ifstream qualified(marker);
  std::string release;
  std::getline(qualified, release);
  Require(release == kernel.release, "capability probe does not match the running kernel");
}
}

int main(int argc, char** argv) {
  if (argc == 2 && std::string(argv[1]) == "--worker") return Worker();
  try {
    Require(argc == 4, "usage: kernel-tests BASELINE_PREFIX CANDIDATE_PREFIX OUTPUT");
    fs::path output = fs::canonical(argv[3]);
    uid_t uid = std::stoul(Environment("SUDO_UID"));
    gid_t gid = std::stoul(Environment("SUDO_GID"));
    Guard(output, uid);
    signal(SIGINT, OnSignal);
    signal(SIGTERM, OnSignal);
    std::ofstream events(output / "events.jsonl", std::ios::out | std::ios::app);
    std::ofstream summary(output / "summary.json");
    Require(events.good() && summary.good(), "cannot open evidence files");
    Disk disk;
    disk.Create(output);
    events << "{\"stage\":\"owned_disk\",\"device\":" << Quote(disk.device)
           << ",\"major\":" << major(disk.device_stat.st_rdev)
           << ",\"minor\":" << minor(disk.device_stat.st_rdev)
           << ",\"read_only\":true}\n" << std::flush;
    bool passed = true;
    summary << "{\"comparison\":\"old-source-with-build-shim versus candidate\",\"cases\":[";
    bool first = true;
    auto deadline = Clock::now() + std::chrono::minutes(8);
    for (int installation = 0; installation < 2; ++installation) {
      std::string label = installation == 0 ? "source_control" : "candidate";
      fs::path prefix = fs::canonical(argv[installation + 1]);
      for (Fault fault : {Fault::Slab, Fault::Page, Fault::Bio}) {
        std::string error;
        Progress progress;
        try {
          Require(!interrupted && Clock::now() < deadline, "total deadline exceeded or interrupted");
          RunCase(fault, prefix, label, output, disk, uid, gid, events, progress);
        } catch (const CleanupFailure&) {
          throw;
        } catch (const std::exception& failure) {
          error = failure.what();
          passed = false;
        }
        if (!first) summary << ',';
        first = false;
        summary << "{\"installation\":" << Quote(label) << ",\"fault\":" << Quote(Name(fault))
                << ",\"passed\":" << (error.empty() ? "true" : "false")
                << ",\"communication\":" << (progress.communication ? "true" : "false")
                << ",\"bpf_load_and_map_cycles\":" << progress.loaded
                << ",\"observed_faults\":" << progress.faults
                << ",\"unaffected_controls\":" << progress.controls
                << ",\"same_process_recoveries\":" << progress.recoveries
                << ",\"process_cleanup\":" << (progress.cleanup ? "true" : "false")
                << ",\"error\":" << Quote(error) << '}' << std::flush;
      }
    }
    bool cleanup = disk.Cleanup();
    passed = passed && cleanup;
    events << "{\"stage\":\"disk_cleanup\",\"passed\":" << (cleanup ? "true" : "false") << "}\n";
    summary << "],\"cleanup\":" << (cleanup ? "true" : "false")
            << ",\"passed\":" << (passed ? "true" : "false") << "}\n";
    return passed ? 0 : 1;
  } catch (const std::exception& failure) {
    std::cerr << failure.what() << '\n';
    return 1;
  }
}
