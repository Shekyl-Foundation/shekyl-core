// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause
//
// Generated from shekyl_transport_layer::CloseKind. Do not edit.
// The Rust enum is the cause table. This header is the projection
// shekyl_ffi.h includes. A test fails if the two differ.

#ifndef SHEKYL_CLOSE_CAUSE_H
#define SHEKYL_CLOSE_CAUSE_H

#include <stdint.h>

/* One close cause. reply_code is the overlay reply for
   SHEKYL_CLOSE_PROXY_REFUSED and zero for every other kind. */
typedef struct shekyl_close_cause {
    uint8_t kind;
    uint16_t reply_code;
} shekyl_close_cause;

#define SHEKYL_CLOSE_PREFIX_MISMATCH 1
#define SHEKYL_CLOSE_TRANSPORT_HANDSHAKE_FAILED 2
#define SHEKYL_CLOSE_TRANSPORT_TIMEOUT 3
#define SHEKYL_CLOSE_ADMISSION_REFUSED 4
#define SHEKYL_CLOSE_DIAL_FAILED 5
#define SHEKYL_CLOSE_PROXY_REFUSED 6
#define SHEKYL_CLOSE_LEVIN_HANDSHAKE_TIMEOUT 7
#define SHEKYL_CLOSE_LEVIN_HANDSHAKE_REJECTED 8
#define SHEKYL_CLOSE_PEER_CLOSED 9
#define SHEKYL_CLOSE_RECORD_REJECTED 10
#define SHEKYL_CLOSE_SESSION_REFUSED 11
#define SHEKYL_CLOSE_IO_ERROR 12
#define SHEKYL_CLOSE_SEND_QUEUE_FULL 13
#define SHEKYL_CLOSE_LOCAL_CLOSE 14
#endif
