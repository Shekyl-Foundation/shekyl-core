// C-compatible declarations for secure memory primitives exported by Rust.
// These back the epee memwipe / mlocker implementations.

#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void shekyl_memwipe(void *ptr, size_t len);
int  shekyl_mlock(const void *ptr, size_t len);
int  shekyl_munlock(const void *ptr, size_t len);
size_t shekyl_page_size(void);

#ifdef __cplusplus
}
#endif
