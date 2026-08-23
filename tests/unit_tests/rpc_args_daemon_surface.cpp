// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Daemon inbound RPC surface: no `--rpc-login` / `--rpc-ssl*` (Axum plaintext),
//! and no `--confirm-external-bind` — the binds it confirmed are refused now
//! (RPC_TRANSPORT_POSTURE.md RT-1/RT-2, at the Rust bind seam). Wallet-RPC
//! keeps the full listener TLS/auth option set.

#include "gtest/gtest.h"

#include <boost/program_options/options_description.hpp>

#include "rpc/core_rpc_server.h"
#include "rpc/rpc_args.h"

namespace {

bool has_option(const boost::program_options::options_description& desc, const char* name)
{
  return desc.find_nothrow(name, false) != nullptr;
}

} // namespace

TEST(RpcArgsDaemonSurface, DaemonOmitsLoginAndSslFlags)
{
  boost::program_options::options_description desc("daemon");
  cryptonote::rpc_args::init_options(desc, /*any_cert_option=*/false, /*include_listener_tls_auth=*/false);

  EXPECT_TRUE(has_option(desc, "rpc-bind-ip"));
  EXPECT_TRUE(has_option(desc, "rpc-bind-ipv6-address"));
  EXPECT_TRUE(has_option(desc, "rpc-use-ipv6"));
  EXPECT_TRUE(has_option(desc, "rpc-access-control-origins"));
  // Retired with RT-W2: confirmation is not refusal. The flag now reaches
  // the removed-flags shim, which refuses it by name.
  EXPECT_FALSE(has_option(desc, "confirm-external-bind"));
  // Retired with it: the flag parsed into a field nothing read, and a loopback
  // bind failing is a refusal, not something to ignore.
  EXPECT_FALSE(has_option(desc, "rpc-ignore-ipv4"));

  EXPECT_FALSE(has_option(desc, "rpc-login"));
  EXPECT_FALSE(has_option(desc, "rpc-ssl"));
  EXPECT_FALSE(has_option(desc, "rpc-ssl-private-key"));
  EXPECT_FALSE(has_option(desc, "rpc-ssl-certificate"));
  EXPECT_FALSE(has_option(desc, "rpc-ssl-ca-certificates"));
  EXPECT_FALSE(has_option(desc, "rpc-ssl-allowed-fingerprints"));
  EXPECT_FALSE(has_option(desc, "rpc-ssl-allow-chained"));
  EXPECT_FALSE(has_option(desc, "rpc-ssl-allow-any-cert"));
}

TEST(RpcArgsDaemonSurface, WalletRpcKeepsLoginAndSslFlags)
{
  boost::program_options::options_description desc("wallet-rpc");
  cryptonote::rpc_args::init_options(desc, /*any_cert_option=*/true, /*include_listener_tls_auth=*/true);

  EXPECT_TRUE(has_option(desc, "rpc-login"));
  EXPECT_TRUE(has_option(desc, "rpc-ssl"));
  EXPECT_TRUE(has_option(desc, "rpc-ssl-private-key"));
  EXPECT_TRUE(has_option(desc, "rpc-ssl-allow-any-cert"));
}

TEST(RpcArgsDaemonSurface, CoreRpcServerInitOptionsOmitLoginAndSsl)
{
  // shekyld registers options via core_rpc_server::init_options →
  // rpc_args::init_options(..., include_listener_tls_auth=false).
  boost::program_options::options_description desc("shekyld");
  cryptonote::core_rpc_server::init_options(desc);
  EXPECT_FALSE(has_option(desc, "rpc-login"));
  EXPECT_FALSE(has_option(desc, "rpc-ssl"));
  EXPECT_TRUE(has_option(desc, "rpc-bind-ip"));
  EXPECT_TRUE(has_option(desc, "rpc-access-control-origins"));
}
