// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Daemon inbound RPC surface: no `--rpc-login` / `--rpc-ssl*` (Axum plaintext).
//! Wallet-RPC keeps the full listener TLS/auth option set.

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
  EXPECT_TRUE(has_option(desc, "rpc-access-control-origins"));
  EXPECT_TRUE(has_option(desc, "confirm-external-bind"));

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
