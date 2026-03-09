#pragma once

#include <cstddef>
#include <cstdint>
#include "crypto/hash.h"

namespace cryptonote
{

struct IPowSchema
{
  virtual ~IPowSchema() = default;
  virtual bool hash(const void* blob, size_t len, uint64_t height, const crypto::hash* seed_hash, unsigned threads, crypto::hash& out) const = 0;
  virtual void prepare_miner_thread(unsigned index, unsigned concurrency) const = 0;
  virtual const char* name() const = 0;
};

} // namespace cryptonote
