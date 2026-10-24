#include "bio_probe.h"

#include <functional>
#include <iostream>

namespace {

using namespace bpfki::bio_probe;

void Check(bool condition, const std::string& message) {
  if (!condition)
    throw std::runtime_error(message);
}

void Rejects(const std::function<void()>& action, const std::string& message) {
  try {
    action();
  } catch (const bpfki::UnsupportedInjection&) {
    return;
  }
  throw std::runtime_error("accepted " + message);
}

const uint64_t address = 0xffffffff81001004;
const Query query{17, true, "should_fail_bio", 0, address};
const Program program{17, {23, 24}};
const std::string row = "ffffffff81001004  k  should_fail_bio+0x4  ";

void IdentityCases() {
  const auto identity = Select(8, program, 23, {{9, query}});
  Check(identity.borrowed_perf_fd == 9 && identity.borrowed_program_fd == 8 &&
        identity.program_id == 17 && identity.map_id == 23 && identity.address == address,
        "selected a different attachment");
  RequireIdentity(identity, program, 23, query);
  auto foreign = query;
  foreign.program_id = 99;
  Check(Select(8, program, 23, {{10, foreign}, {9, query}}).borrowed_perf_fd == 9,
        "selected a foreign attachment");
  Rejects([&] { Select(8, program, 99, {{9, query}}); }, "a foreign map");
  Rejects([&] { Select(8, program, 23, {}); }, "missing perf FD");
  Rejects([&] { Select(8, program, 23, {{9, query}, {10, query}}); }, "ambiguous perf FDs");
  for (int change = 0; change < 5; ++change) {
    auto changed = query;
    if (change == 0) changed.program_id = 19;
    if (change == 1) changed.entry = false;
    if (change == 2) changed.symbol = "another_hook";
    if (change == 3) changed.offset = 4;
    if (change == 4) changed.address = 0;
    Rejects([&] { Select(8, program, 23, {{9, changed}}); }, "wrong query identity");
    Rejects([&] { RequireIdentity(identity, program, 23, changed); }, "changed perf FD");
  }
  auto moved = query;
  ++moved.address;
  Rejects([&] { RequireIdentity(identity, program, 23, moved); }, "a moved probe");
  Rejects([&] { RequireIdentity(identity, {18, {23}}, 23, query); }, "a reused program FD");
  Rejects([&] { RequireIdentity(identity, {17, {24}}, 23, query); }, "a detached ctxs map");
  Rejects([&] { RequireIdentity(identity, program, 24, query); }, "a reused map FD");
}

void ModeCases() {
  RequireFtrace(row + "[FTRACE]\n", address);
  RequireFtrace(row + "[FTRACE]\n" + row + "[FTRACE]\n", address);
  RequireFtrace(row + "[FTRACE]\nffffffff81001004 r should_fail_bio+0x4 [FTRACE]\n", address);
  RequireFtrace("ffffffff81001004 k should_fail_bio+0x10 [FTRACE]\n", address);
  RequireFtrace("ffffffff81002000 k unrelated+0x0 [OPTIMIZED]\n" + row + "[FTRACE]\n", address);
  const std::vector<std::string> invalid_flags{
      "", "[OPTIMIZED]", "[DISABLED]", "[GONE]", "[UNKNOWN]",
      "[FTRACE][OPTIMIZED]", "[FTRACE] [DISABLED]", "[GONE][FTRACE]",
      "[FTRACE][UNKNOWN]", "[FTRACE]tail", "[FTRACE", "[FTRACE] [FTRACE]"};
  for (const auto& flags : invalid_flags)
    Rejects([&] { RequireFtrace(row + flags + "\n", address); }, "mode flags " + flags);
  const std::vector<std::string> invalid_listings{
      "", row + "[FTRACE]", row + "[FTRACE]\n" + row + "\n",
      row + "[FTRACE]\n" + row + "[OPTIMIZED]\n",
      row + "[FTRACE]\nffffffff81001004 r should_fail_bio+0x4 [DISABLED]\n",
      row + "[FTRACE]\nffffffff81001004 k should_fail_bio+0x0 [FTRACE]\n",
      "ffffffff81001004 r should_fail_bio+0x4 [FTRACE]\n",
      "ffffffff81001004 k should_fail_bio+0x4junk [FTRACE]\n",
      "ffffffff81001004 k other+0x4 [FTRACE]\n",
      "ffffffff81001004x k should_fail_bio+0x4 [FTRACE]\n",
      "ffffffff81002000 k should_fail_bio+0x4 [FTRACE]\n",
      "ffffffff81001004 k\n", row + "[FTRACE]" + std::string(1, '\0') + "\n"};
  for (const auto& listing : invalid_listings)
    Rejects([&] { RequireFtrace(listing, address); }, "missing, inconsistent, or malformed mode metadata");
}

}

int main() {
  try {
    IdentityCases();
    ModeCases();
    std::cout << "PASS: BIO owned identity and complete FTRACE metadata policy.\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
