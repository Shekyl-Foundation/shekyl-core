#include "crypto/pow_registry.h"

namespace cryptonote
{

namespace
{
const IPowSchema* s_pow_schema_override_for_tests = nullptr;
} // namespace

void set_pow_schema_override_for_tests(const IPowSchema* schema)
{
  s_pow_schema_override_for_tests = schema;
}

const IPowSchema& get_pow_for_height(uint64_t /*height*/, uint8_t /*block_version*/)
{
  if (s_pow_schema_override_for_tests)
    return *s_pow_schema_override_for_tests;
  return get_randomx_pow_schema();
}

} // namespace cryptonote
