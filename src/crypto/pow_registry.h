#pragma once

#include <cstdint>
#include "crypto/pow_schema.h"

namespace cryptonote
{

const IPowSchema& get_pow_for_height(uint64_t height, uint8_t block_version);

const IPowSchema& get_randomx_pow_schema();

} // namespace cryptonote
