#pragma once

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace bpfki {
namespace filter_layout {

#define BPFKI_FILTER_FIELDS(X) \
  X(pct) \
  X(max_inject_times) \
  X(inject_times) \
  X(ignore) \
  X(curr_call) \
  X(conds_met)

enum Field : size_t {
#define BPFKI_FILTER_INDEX(name) name,
  BPFKI_FILTER_FIELDS(BPFKI_FILTER_INDEX)
#undef BPFKI_FILTER_INDEX
  field_count
};

static_assert(sizeof(uint64_t) == 8, "filter words must be eight bytes");
static_assert(alignof(uint64_t) == 8, "filter words must be eight-byte aligned");
inline constexpr uint64_t probability_scale = uint64_t{1} << 32;

struct Condition {
  uint64_t threshold;
  uint32_t limit;
};

inline Condition ParseCondition(float probability, uint32_t times) {
  if (!std::isfinite(probability) || probability < 0 || probability > 1)
    throw std::invalid_argument("probability must be finite and between 0 and 1");
  return {static_cast<uint64_t>(static_cast<double>(probability) *
                                probability_scale), times};
}

inline size_t ValueSize(size_t stack_slots) {
  if (stack_slots == 0 ||
      stack_slots > std::numeric_limits<size_t>::max() / sizeof(uint64_t) - field_count)
    throw std::invalid_argument("invalid filter stack size");
  const size_t bytes = (field_count + stack_slots) * sizeof(uint64_t);
  if (bytes > std::numeric_limits<uint32_t>::max())
    throw std::invalid_argument("filter value exceeds BPF map size limit");
  return bytes;
}

inline std::vector<uint64_t> InitialWords(size_t stack_slots, Condition condition) {
  std::vector<uint64_t> words(ValueSize(stack_slots) / sizeof(uint64_t), 0);
  words[pct] = condition.threshold;
  words[max_inject_times] = condition.limit;
  return words;
}

inline std::string BpfDeclaration(size_t stack_slots) {
  const size_t bytes = ValueSize(stack_slots);
  std::string declaration = "struct fk_ctx {\n";
#define BPFKI_FILTER_DECLARE(name) declaration += "    u64 " #name ";\n";
  BPFKI_FILTER_FIELDS(BPFKI_FILTER_DECLARE)
#undef BPFKI_FILTER_DECLARE
  declaration += "    u64 stack[" + std::to_string(stack_slots) + "];\n};\n";
#define BPFKI_FILTER_ASSERT(name) \
  declaration += "_Static_assert(__builtin_offsetof(struct fk_ctx, " #name \
      ") == " + std::to_string(name * sizeof(uint64_t)) + \
      ", \"filter " #name " offset\");\n";
  BPFKI_FILTER_FIELDS(BPFKI_FILTER_ASSERT)
#undef BPFKI_FILTER_ASSERT
  declaration += "_Static_assert(__builtin_offsetof(struct fk_ctx, stack) == " +
      std::to_string(field_count * sizeof(uint64_t)) +
      ", \"filter stack offset\");\n";
  declaration += "_Static_assert(__alignof__(struct fk_ctx) == 8, \"filter alignment\");\n";
  declaration += "_Static_assert(sizeof(struct fk_ctx) == " + std::to_string(bytes) +
      ", \"filter value size\");\n";
  return declaration;
}

#undef BPFKI_FILTER_FIELDS

}
}
