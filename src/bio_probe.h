#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace bpfki {

class UnsupportedInjection final : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

namespace bio_probe {

struct Query {
  uint32_t program_id;
  bool entry;
  std::string symbol;
  uint64_t offset;
  uint64_t address;
};

struct Program {
  uint32_t id;
  std::vector<uint32_t> map_ids;
};

struct Identity {
  int borrowed_perf_fd;
  int borrowed_program_fd;
  uint32_t program_id;
  uint32_t map_id;
  uint64_t address;
};

Identity Identify(int perf_fd, int program_fd, const Program& program,
                  uint32_t map_id, const Query& query);
void RequireIdentity(const Identity& identity, const Program& program,
                     uint32_t map_id, const Query& query);
void RequireFtrace(const std::string& listing, uint64_t address);

Identity Capture(int perf_fd, int program_fd, int map_fd);
void Recheck(const Identity& identity, int map_fd);

}
}
