#include "crypto/pow_registry.h"

#include <atomic>

namespace cryptonote
{

namespace
{
// Atomic because get_pow_for_height is read from the longhash precompute
// worker threads (blockchain.cpp's tpool.submit), so a seam that is only
// safe as long as nobody writes it while they run is correct by argument
// rather than by construction. Relaxed suffices: the pointer carries no
// ordering dependency on other data -- the schemas it selects are immutable
// -- so a worker seeing either the old or the new value is well-defined
// either way. Production never writes it; the read is a plain load.
std::atomic<const IPowSchema*> s_pow_schema_override_for_tests{nullptr};
} // namespace

void set_pow_schema_override_for_tests(const IPowSchema* schema)
{
  s_pow_schema_override_for_tests.store(schema, std::memory_order_relaxed);
}

const IPowSchema& get_pow_for_height(uint64_t /*height*/, uint8_t /*block_version*/)
{
  const IPowSchema* const override_schema =
    s_pow_schema_override_for_tests.load(std::memory_order_relaxed);
  if (override_schema)
    return *override_schema;
  return get_randomx_pow_schema();
}

} // namespace cryptonote
