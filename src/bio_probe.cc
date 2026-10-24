#include "bio_probe.h"

#include <algorithm>
#include <charconv>
#include <optional>
#include <sstream>
#include <string_view>

namespace bpfki {
namespace bio_probe {
namespace {

[[noreturn]] void Reject(const std::string& reason) {
  throw UnsupportedInjection("BIO unsupported: " + reason);
}

bool IsTarget(const Query& query) {
  return query.entry && query.symbol == "should_fail_bio" &&
         query.offset == 0 && query.address != 0;
}

bool HasMap(const Program& program, uint32_t map_id) {
  return program.id != 0 && map_id != 0 &&
         std::find(program.map_ids.begin(), program.map_ids.end(), map_id) !=
             program.map_ids.end();
}

uint64_t Hex(std::string_view text) {
  uint64_t value = 0;
  const auto result = std::from_chars(text.data(), text.data() + text.size(), value, 16);
  if (text.empty() || result.ec != std::errc{} || result.ptr != text.data() + text.size())
    Reject("malformed kprobes address or symbol offset");
  return value;
}

}

Identity Select(int program_fd, const Program& program, uint32_t map_id,
                const std::vector<std::pair<int, Query>>& added) {
  if (program_fd < 0 || !HasMap(program, map_id))
    Reject("owned program does not reference its ctxs map");
  std::optional<Identity> selected;
  for (const auto& candidate : added) {
    const auto& query = candidate.second;
    if (query.program_id != program.id || !IsTarget(query))
      continue;
    if (candidate.first < 0 || selected)
      Reject("ambiguous owned should_fail_bio perf FD");
    selected = Identity{candidate.first, program_fd, program.id, map_id, query.address};
  }
  if (!selected)
    Reject("no owned should_fail_bio entry perf FD with logical offset zero");
  return *selected;
}

void RequireIdentity(const Identity& identity, const Program& program,
                     uint32_t map_id, const Query& query) {
  if (identity.borrowed_perf_fd < 0 || identity.borrowed_program_fd < 0 ||
      identity.program_id != program.id || identity.map_id != map_id ||
      !HasMap(program, map_id) || query.program_id != identity.program_id ||
      !IsTarget(query) || query.address != identity.address)
    Reject("owned should_fail_bio perf FD, program, or ctxs map changed");
}

void RequireFtrace(const std::string& listing, uint64_t address) {
  if (address == 0 || listing.empty() || listing.back() != '\n' ||
      listing.find('\0') != std::string::npos)
    Reject("missing or incomplete kprobes metadata");
  std::istringstream input(listing);
  std::string line;
  std::optional<uint64_t> symbol_offset;
  bool entry_found = false;
  while (std::getline(input, line)) {
    std::istringstream fields(line);
    std::string raw_address, kind, symbol;
    if (!(fields >> raw_address >> kind >> symbol))
      Reject("malformed kprobes record");
    if (Hex(raw_address) != address)
      continue;
    constexpr std::string_view prefix = "should_fail_bio+0x";
    if ((kind != "k" && kind != "r") || symbol.compare(0, prefix.size(), prefix) != 0)
      Reject("inconsistent symbol or probe type at the owned BIO address");
    const auto offset = Hex(std::string_view(symbol).substr(prefix.size()));
    if (symbol_offset && *symbol_offset != offset)
      Reject("inconsistent symbol offsets at the owned BIO address");
    symbol_offset = offset;
    std::string flags;
    std::getline(fields, flags);
    bool ftrace = false;
    size_t position = 0;
    while (position < flags.size()) {
      if (flags[position] == ' ' || flags[position] == '\t') {
        ++position;
        continue;
      }
      const auto end = flags.find(']', position);
      if (flags[position] != '[' || end == std::string::npos)
        Reject("malformed owned BIO mode flags");
      const auto flag = flags.substr(position, end - position + 1);
      if (flag != "[FTRACE]" || ftrace)
        Reject("owned BIO mode " + flag + "; only live FTRACE is supported");
      ftrace = true;
      position = end + 1;
    }
    if (!ftrace)
      Reject("owned BIO probe is not FTRACE; plain and optimized kprobes are unsupported");
    entry_found = entry_found || kind == "k";
  }
  if (!entry_found)
    Reject("no live FTRACE entry record at the owned BIO address");
}

}
}
