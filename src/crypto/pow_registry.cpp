#include "crypto/pow_registry.h"

#include "crypto/hash-ops.h"

namespace cryptonote
{

int get_cryptonight_variant_for_block(uint8_t block_version)
{
  return block_version >= 7 ? block_version - 6 : 0;
}

const IPowSchema& get_pow_for_height(uint64_t /*height*/, uint8_t block_version)
{
  if (block_version >= RX_BLOCK_VERSION)
    return get_randomx_pow_schema();

  return get_cryptonight_pow_schema(get_cryptonight_variant_for_block(block_version));
}

} // namespace cryptonote
