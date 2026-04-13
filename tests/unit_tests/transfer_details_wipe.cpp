// Copyright (c) 2024-2026, The Shekyl Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted per the Shekyl license.

#include "gtest/gtest.h"
#include "wallet/wallet2.h"
#include <cstring>

static const uint8_t SENTINEL = 0xAA;

static bool is_zeroed(const void* ptr, size_t len)
{
    const auto* p = static_cast<const volatile uint8_t*>(ptr);
    for (size_t i = 0; i < len; ++i)
    {
        if (p[i] != 0)
            return false;
    }
    return true;
}

TEST(transfer_details_wipe, secret_fields_zeroed_after_destruction)
{
    const void* mask_addr = nullptr;
    const void* y_addr = nullptr;
    const void* k_amount_addr = nullptr;
    const void* css_addr = nullptr;
    size_t css_size = 0;

    {
        tools::wallet2::transfer_details td;

        memset(td.m_mask.data, SENTINEL, sizeof(td.m_mask.data));
        memset(td.m_y.data, SENTINEL, sizeof(td.m_y.data));
        memset(td.m_k_amount.data, SENTINEL, sizeof(td.m_k_amount.data));
        memset(td.m_combined_shared_secret.data(), SENTINEL, td.m_combined_shared_secret.size());

        mask_addr = td.m_mask.data;
        y_addr = td.m_y.data;
        k_amount_addr = td.m_k_amount.data;
        css_addr = td.m_combined_shared_secret.data();
        css_size = td.m_combined_shared_secret.size();

        ASSERT_FALSE(is_zeroed(mask_addr, 32)) << "DEBUG: sentinel not written to m_mask";
        ASSERT_FALSE(is_zeroed(y_addr, 32)) << "DEBUG: sentinel not written to m_y";
        ASSERT_FALSE(is_zeroed(k_amount_addr, 32)) << "DEBUG: sentinel not written to m_k_amount";
        ASSERT_FALSE(is_zeroed(css_addr, css_size)) << "DEBUG: sentinel not written to m_combined_shared_secret";
    }

    EXPECT_TRUE(is_zeroed(mask_addr, 32))
        << "m_mask was NOT wiped after transfer_details destruction";
    EXPECT_TRUE(is_zeroed(y_addr, 32))
        << "m_y was NOT wiped after transfer_details destruction";
    EXPECT_TRUE(is_zeroed(k_amount_addr, 32))
        << "m_k_amount was NOT wiped after transfer_details destruction";
    EXPECT_TRUE(is_zeroed(css_addr, css_size))
        << "m_combined_shared_secret was NOT wiped after transfer_details destruction";
}
