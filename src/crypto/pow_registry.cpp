#include "crypto/pow_registry.h"

namespace cryptonote
{

const IPowSchema& get_pow_for_height(uint64_t /*height*/, uint8_t /*block_version*/)
{
  return get_randomx_pow_schema();
}

} // namespace cryptonote
