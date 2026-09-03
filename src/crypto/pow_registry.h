#pragma once

#include <cstdint>
#include "crypto/pow_schema.h"

namespace cryptonote
{

const IPowSchema& get_pow_for_height(uint64_t height, uint8_t block_version);

const IPowSchema& get_randomx_pow_schema();

// TEST SEAM — production code must never call this (grep-gated by the loud
// name). Installs a schema returned by get_pow_for_height in place of the
// RandomX schema so unit tests can exercise the verifier-failure arms
// (CEN-D2: a longhash the verifier could not compute must reject the block
// at every difficulty, including 1, where the 0xff sentinel passes
// check_hash). Pass nullptr to restore the real schema.
void set_pow_schema_override_for_tests(const IPowSchema* schema);

} // namespace cryptonote
