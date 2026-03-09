#include "crypto/pow_registry.h"

#include "crypto/hash-ops.h"

namespace cryptonote
{
namespace
{
class RandomXPowSchema final : public IPowSchema
{
public:
  bool hash(const void* blob, size_t len, uint64_t /*height*/, const crypto::hash* seed_hash, unsigned /*threads*/, crypto::hash& out) const override
  {
    if (seed_hash == nullptr)
      return false;
    crypto::rx_slow_hash(seed_hash->data, blob, len, out.data);
    return true;
  }

  void prepare_miner_thread(unsigned index, unsigned concurrency) const override
  {
    crypto::rx_set_miner_thread(index, concurrency);
  }

  const char* name() const override
  {
    return "RandomX";
  }
};
} // namespace

const IPowSchema& get_randomx_pow_schema()
{
  static const RandomXPowSchema schema{};
  return schema;
}

} // namespace cryptonote
