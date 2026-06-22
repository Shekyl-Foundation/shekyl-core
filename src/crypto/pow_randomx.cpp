#include "crypto/pow_registry.h"

#include "crypto/hash-ops.h"

#include "shekyl/shekyl_ffi.h"

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
#ifdef SHEKYL_RANDOMX_V2_VERIFY
    if (shekyl_pow_randomx_v2_hash(
          reinterpret_cast<const uint8_t (*)[32]>(seed_hash->data),
          static_cast<const uint8_t*>(blob),
          len,
          reinterpret_cast<uint8_t (*)[32]>(out.data)) != SHEKYL_POW_RANDOMX_V2_OK)
      return false;
#else
    crypto::rx_slow_hash(seed_hash->data, blob, len, out.data);
#endif
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
