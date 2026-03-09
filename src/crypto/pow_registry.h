#pragma once

#include <cstdint>
#include "crypto/pow_schema.h"

namespace cryptonote
{

int get_cryptonight_variant_for_block(uint8_t block_version);
const IPowSchema& get_pow_for_height(uint64_t height, uint8_t block_version);

const IPowSchema& get_randomx_pow_schema();
const IPowSchema& get_cryptonight_pow_schema(int variant);

} // namespace cryptonote
