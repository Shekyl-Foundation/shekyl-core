#pragma once

// Canonical Shekyl version symbols
extern const char* const SHEKYL_VERSION_TAG;
extern const char* const SHEKYL_VERSION;
extern const char* const SHEKYL_RELEASE_NAME;
extern const char* const SHEKYL_VERSION_FULL;
extern const bool SHEKYL_VERSION_IS_RELEASE;

// Legacy Monero compatibility aliases -- kept so upstream cherry-picks
// compile without touching every call site.  Remove once Monero merge
// dependency is fully retired (post-v4 RingPQC).
#define MONERO_VERSION_TAG      SHEKYL_VERSION_TAG
#define MONERO_VERSION          SHEKYL_VERSION
#define MONERO_RELEASE_NAME     SHEKYL_RELEASE_NAME
#define MONERO_VERSION_FULL     SHEKYL_VERSION_FULL
#define MONERO_VERSION_IS_RELEASE SHEKYL_VERSION_IS_RELEASE
