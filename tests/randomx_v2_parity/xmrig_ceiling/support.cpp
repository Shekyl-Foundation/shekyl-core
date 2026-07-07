// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause
//
// NOTE: this dev-only harness is BUILT against a local XMRig clone (GPLv3, via
// XMRIG_DIR); XMRig is neither vendored nor distributed here. The built binary
// is GPLv3 by linkage and is not distributed. This source, as authored by The
// Shekyl Foundation, is BSD-3-Clause.

#include <cstdio>
#include <cstring>
#include <cerrno>
// Minimal honest support layer for standalone XMRig-RandomX linkage.
//
// XMRig's RandomX calls into XMRig's base library (Cpu/VirtualMemory/Chrono)
// and uses the rx_blake2b dispatch pointer normally defined in src/crypto/rx/Rx.cpp.
// For a Phase-0 hash-CORRECTNESS harness these are provided honestly:
//   - Chrono: real monotonic clock (only used to time-select soft-AES variants).
//   - VirtualMemory: malloc/mmap-backed (allocation METHOD is hash-irrelevant).
//   - Cpu::info(): reports NO special features -> RandomX uses the portable
//     soft-AES path and no JIT codegen tweaks. RandomX mandates soft-AES output
//     == hard-AES output, so this faithfully exercises XMRig's algorithm code;
//     hardware AES / BMI2 / VAES are PERFORMANCE levers (Phase 1), not Phase 0.

#include <cstddef>
#include <cstdint>
#include <vector>
#include <chrono>
#include <sys/mman.h>

#include "crypto/randomx/blake2/blake2.h"
#include "backend/cpu/Cpu.h"
#include "backend/cpu/interfaces/ICpuInfo.h"
#include "crypto/common/VirtualMemory.h"
#include "base/tools/Chrono.h"
#include "3rdparty/rapidjson/document.h"

// RandomX blake2b dispatch pointers (normally defined in src/crypto/rx/Rx.cpp:94-95).
int (*rx_blake2b)(void *out, size_t outlen, const void *in, size_t inlen) = rx_blake2b_default;
void (*rx_blake2b_compress)(blake2b_state *S, const uint8_t *block) = rx_blake2b_compress_integer;

// libuv's uv_hrtime, used only to benchmark-select the Argon2 impl (output-irrelevant).
extern "C" uint64_t uv_hrtime(void)
{
    using namespace std::chrono;
    return duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count();
}

namespace xmrig {

double Chrono::highResolutionMSecs()
{
    using namespace std::chrono;
    return duration<double, std::milli>(steady_clock::now().time_since_epoch()).count();
}

void *VirtualMemory::allocateExecutableMemory(size_t size, bool)
{
    void *p = mmap(nullptr, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p != MAP_FAILED) { return p; }
    // Kernel may forbid PROT_EXEC on a fresh W|X mapping; map RW then flip to RWX.
    p = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        fprintf(stderr, "allocateExecutableMemory: mmap failed size=%zu errno=%d (%s)\n",
                size, errno, strerror(errno));
        return nullptr;
    }
    if (mprotect(p, size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        fprintf(stderr, "allocateExecutableMemory: mprotect RWX failed errno=%d (%s)\n",
                errno, strerror(errno));
        munmap(p, size);
        return nullptr;
    }
    return p;
}

void *VirtualMemory::allocateLargePagesMemory(size_t) { return nullptr; } // -> normal-page fallback
void VirtualMemory::freeLargePagesMemory(void *, size_t) {}
void VirtualMemory::flushInstructionCache(void *, size_t) {}
bool VirtualMemory::protectRW(void *p, size_t size) { return mprotect(p, size, PROT_READ | PROT_WRITE) == 0; }
bool VirtualMemory::protectRX(void *p, size_t size) { return mprotect(p, size, PROT_READ | PROT_EXEC) == 0; }

class StubCpuInfo : public ICpuInfo
{
public:
    Arch arch() const override { return ARCH_UNKNOWN; }
    Assembly::Id assembly() const override { return Assembly::NONE; }
    bool has(Flag) const override { return false; }
    bool hasAES() const override { return false; }
    bool hasVAES() const override { return false; }
    bool hasAVX() const override { return false; }
    bool hasAVX2() const override { return false; }
    bool hasBMI2() const override { return false; }
    bool hasCatL3() const override { return false; }
    bool hasOneGbPages() const override { return false; }
    bool hasXOP() const override { return false; }
    bool isVM() const override { return false; }
    bool hasRISCV_Vector() const override { return false; }
    bool jccErratum() const override { return false; }
    const char *backend() const override { return "stub"; }
    const char *brand() const override { return "stub"; }
    const std::vector<int32_t> &units() const override { static std::vector<int32_t> v{0}; return v; }
    CpuThreads threads(const Algorithm &, uint32_t) const override { return CpuThreads(); }
    MsrMod msrMod() const override { return MSR_MOD_NONE; }
    rapidjson::Value toJSON(rapidjson::Document &) const override { return rapidjson::Value(rapidjson::kNullType); }
    size_t cores() const override { return 1; }
    size_t L2() const override { return 0; }
    size_t L3() const override { return 0; }
    size_t nodes() const override { return 1; }
    size_t packages() const override { return 1; }
    size_t threads() const override { return 1; }
    Vendor vendor() const override { return VENDOR_UNKNOWN; }
    uint32_t model() const override { return 0; }
};

ICpuInfo *Cpu::info()
{
    static StubCpuInfo s;
    return &s;
}

} // namespace xmrig
