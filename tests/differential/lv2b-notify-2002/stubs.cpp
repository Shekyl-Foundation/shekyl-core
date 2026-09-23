// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// Stubs for the Rust-owned FFI symbols epee links against. None participates
// in portable-storage encoding; they exist only to satisfy the linker.
#include <cstddef>
#include <cstdint>
#include <cstring>
extern "C" {
void shekyl_memwipe(void* p, size_t n) { if (p && n) std::memset(p, 0, n); }
int  shekyl_mlock(void*, size_t) { return 0; }
int  shekyl_munlock(void*, size_t) { return 0; }
size_t shekyl_page_size(void) { return 4096; }
void shekyl_log_emit(int, const char*, const char*, int, const char*) {}
int  shekyl_log_level_enabled(int, const char*) { return 0; }
}
