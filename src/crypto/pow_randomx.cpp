#include "crypto/pow_registry.h"

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
    if (shekyl_pow_randomx_v2_hash(
          reinterpret_cast<const uint8_t (*)[32]>(seed_hash->data),
          static_cast<const uint8_t*>(blob),
          len,
          reinterpret_cast<uint8_t (*)[32]>(out.data)) != SHEKYL_POW_RANDOMX_V2_OK)
      return false;
    return true;
  }

  void prepare_miner_thread(unsigned /*index*/, unsigned /*concurrency*/) const override
  {
    // Deliberately a no-op. The old body called crypto::rx_set_miner_thread,
    // which unconditionally allocated a ~2 GiB *v1* RandomX dataset
    // (ignore_env=1 bypassed the MONERO_RANDOMX_FULL_MEM opt-in) and then
    // launched dataset-init threads against a never-seeded NULL cache — the
    // v1 hashing path has had no consumer since the 3b cutover (consensus and
    // the in-tree miner both hash via shekyl_pow_randomx_v2_hash above), so
    // the only live seeder of that cache was already dead and every
    // release-build start_mining segfaulted (NDEBUG compiles out the
    // upstream assert(cache != nullptr); debug builds aborted on it). The
    // Rust verifier needs no per-thread preparation: its VM pool and
    // canonical cache are process-global, fed by
    // shekyl_pow_randomx_v2_set_canonical at tip advance.
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
