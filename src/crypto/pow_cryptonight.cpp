#include "crypto/pow_registry.h"

#include <array>
#include <algorithm>
#include "crypto/hash.h"

namespace cryptonote
{
namespace
{
constexpr int MAX_CRYPTONIGHT_VARIANT = 16;

class CryptonightPowSchema final : public IPowSchema
{
public:
  explicit CryptonightPowSchema(int variant)
    : m_variant(variant)
  {
  }

  bool hash(const void* blob, size_t len, uint64_t height, const crypto::hash* /*seed_hash*/, unsigned /*threads*/, crypto::hash& out) const override
  {
    crypto::cn_slow_hash(blob, len, out, m_variant, height);
    return true;
  }

  void prepare_miner_thread(unsigned /*index*/, unsigned /*concurrency*/) const override
  {
  }

  const char* name() const override
  {
    return "Cryptonight";
  }

private:
  int m_variant;
};
} // namespace

const IPowSchema& get_cryptonight_pow_schema(int variant)
{
  static const auto schemas = []() {
    std::array<CryptonightPowSchema, MAX_CRYPTONIGHT_VARIANT> out = {
      CryptonightPowSchema(0), CryptonightPowSchema(1), CryptonightPowSchema(2), CryptonightPowSchema(3),
      CryptonightPowSchema(4), CryptonightPowSchema(5), CryptonightPowSchema(6), CryptonightPowSchema(7),
      CryptonightPowSchema(8), CryptonightPowSchema(9), CryptonightPowSchema(10), CryptonightPowSchema(11),
      CryptonightPowSchema(12), CryptonightPowSchema(13), CryptonightPowSchema(14), CryptonightPowSchema(15)
    };
    return out;
  }();
  const int clamped = std::max(0, std::min(variant, MAX_CRYPTONIGHT_VARIANT - 1));
  return schemas[clamped];
}

} // namespace cryptonote
