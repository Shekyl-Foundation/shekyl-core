#include "crypto/pow_registry.h"

#include <atomic>

namespace cryptonote
{

namespace
{
// Atomic because get_pow_for_height is read from the longhash precompute
// worker threads (blockchain.cpp's tpool.submit), so a seam that is only
// safe as long as nobody writes it while they run is correct by argument
// rather than by construction.
//
// Release/acquire, not relaxed: the store must PUBLISH the schema object,
// not merely the pointer. A worker that observed the new pointer without an
// acquire would have no happens-before edge to that schema's construction,
// so reading its vptr or fields would be a race on initialisation even
// though the object never mutates afterwards. The pair supplies that edge;
// the acquire load is free on x86 and one instruction on ARM, against a
// RandomX hash of work behind it.
std::atomic<const IPowSchema*> s_pow_schema_override_for_tests{nullptr};
} // namespace

void set_pow_schema_override_for_tests(const IPowSchema* schema)
{
  s_pow_schema_override_for_tests.store(schema, std::memory_order_release);
}

const IPowSchema& get_pow_for_height(uint64_t /*height*/, uint8_t /*block_version*/)
{
  const IPowSchema* const override_schema =
    s_pow_schema_override_for_tests.load(std::memory_order_acquire);
  if (override_schema)
    return *override_schema;
  return get_randomx_pow_schema();
}

} // namespace cryptonote
