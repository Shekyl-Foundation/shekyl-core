// Copyright (c) 2014-2022, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include "gtest/gtest.h"

#include <cstdint>
#include <algorithm>
#include <sstream>

#include "ringct/rctTypes.h"
#include "ringct/rctSigs.h"
#include "ringct/rctOps.h"
#include "device/device.hpp"
#include "string_tools.h"

using namespace std;
using namespace crypto;
using namespace rct;

TEST(ringct, CLSAG)
{
  const size_t N = 11;
  const size_t idx = 5;
  ctkeyV pubs;
  key p, t, t2, u;
  const key message = identity();
  ctkey backup;
  clsag clsag;

  for (size_t i = 0; i < N; ++i)
  {
    key sk;
    ctkey tmp;

    skpkGen(sk, tmp.dest);
    skpkGen(sk, tmp.mask);

    pubs.push_back(tmp);
  }

  // Set P[idx]
  skpkGen(p, pubs[idx].dest);

  // Set C[idx]
  t = skGen();
  u = skGen();
  addKeys2(pubs[idx].mask,t,u,H);

  // Set commitment offset
  key Cout;
  t2 = skGen();
  addKeys2(Cout,t2,u,H);

  // Prepare generation inputs
  ctkey insk;
  insk.dest = p;
  insk.mask = t;
  
  // bad message
  clsag = rct::proveRctCLSAGSimple(zero(),pubs,insk,t2,Cout,idx,hw::get_device("default"));
  ASSERT_FALSE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));

  // bad index at creation
  try
  {
    clsag = rct::proveRctCLSAGSimple(message,pubs,insk,t2,Cout,(idx + 1) % N,hw::get_device("default"));
    ASSERT_FALSE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));
  }
  catch (...) { /* either exception, or failure to verify above */ }

  // bad z at creation
  try
  {
    ctkey insk2;
    insk2.dest = insk.dest;
    insk2.mask = skGen();
    clsag = rct::proveRctCLSAGSimple(message,pubs,insk2,t2,Cout,idx,hw::get_device("default"));
    ASSERT_FALSE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));
  }
  catch (...) { /* either exception, or failure to verify above */ }

  // bad C at creation
  backup = pubs[idx];
  pubs[idx].mask = scalarmultBase(skGen());
  try
  {
    clsag = rct::proveRctCLSAGSimple(message,pubs,insk,t2,Cout,idx,hw::get_device("default"));
    ASSERT_FALSE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));
  }
  catch (...) { /* either exception, or failure to verify above */ }
  pubs[idx] = backup;

  // bad p at creation
  try
  {
    ctkey insk2;
    insk2.dest = skGen();
    insk2.mask = insk.mask;
    clsag = rct::proveRctCLSAGSimple(message,pubs,insk2,t2,Cout,idx,hw::get_device("default"));
    ASSERT_FALSE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));
  }
  catch (...) { /* either exception, or failure to verify above */ }

  // bad P at creation
  backup = pubs[idx];
  pubs[idx].dest = scalarmultBase(skGen());
  try
  {
    clsag = rct::proveRctCLSAGSimple(message,pubs,insk,t2,Cout,idx,hw::get_device("default"));
    ASSERT_FALSE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));
  }
  catch (...) { /* either exception, or failure to verify above */ }
  pubs[idx] = backup;

  // Test correct signature
  clsag = rct::proveRctCLSAGSimple(message,pubs,insk,t2,Cout,idx,hw::get_device("default"));
  ASSERT_TRUE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));

  // empty s
  auto sbackup = clsag.s;
  clsag.s.clear();
  ASSERT_FALSE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));
  clsag.s = sbackup;

  // too few s elements
  key backup_key;
  backup_key = clsag.s.back();
  clsag.s.pop_back();
  ASSERT_FALSE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));
  clsag.s.push_back(backup_key);

  // too many s elements
  clsag.s.push_back(skGen());
  ASSERT_FALSE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));
  clsag.s.pop_back();

  // bad s in clsag at verification
  for (auto &s: clsag.s)
  {
    backup_key = s;
    s = skGen();
    ASSERT_FALSE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));
    s = backup_key;
  }

  // bad c1 in clsag at verification
  backup_key = clsag.c1;
  clsag.c1 = skGen();
  ASSERT_FALSE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));
  clsag.c1 = backup_key;

  // bad I in clsag at verification
  backup_key = clsag.I;
  clsag.I = scalarmultBase(skGen());
  ASSERT_FALSE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));
  clsag.I = backup_key;

  // bad D in clsag at verification
  backup_key = clsag.D;
  clsag.D = scalarmultBase(skGen());
  ASSERT_FALSE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));
  clsag.D = backup_key;

  // D not in main subgroup in clsag at verification
  backup_key = clsag.D;
  rct::key x;
  ASSERT_TRUE(epee::string_tools::hex_to_pod("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", x));
  clsag.D = rct::addKeys(clsag.D, x);
  ASSERT_FALSE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));
  clsag.D = backup_key;

  // swapped I and D in clsag at verification
  std::swap(clsag.I, clsag.D);
  ASSERT_FALSE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));
  std::swap(clsag.I, clsag.D);

  // check it's still good, in case we failed to restore
  ASSERT_TRUE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));
}

TEST(ringct, HPow2)
{
  key G = scalarmultBase(d2h(1));

  // Note that H is computed differently than standard hashing
  // This method is not guaranteed to return a curvepoint for all inputs
  // Don't use it elsewhere
  key H = cn_fast_hash(G);
  ge_p3 H_p3;
  int decode = ge_frombytes_vartime(&H_p3, H.bytes);
  ASSERT_EQ(decode, 0); // this is known to pass for the particular value G
  ge_p2 H_p2;
  ge_p3_to_p2(&H_p2, &H_p3);
  ge_p1p1 H8_p1p1;
  ge_mul8(&H8_p1p1, &H_p2);
  ge_p1p1_to_p3(&H_p3, &H8_p1p1);
  ge_p3_tobytes(H.bytes, &H_p3);

  for (int j = 0 ; j < ATOMS ; j++) {
    ASSERT_TRUE(equalKeys(H, H2[j]));
    addKeys(H, H, H);
  }
}

static const xmr_amount test_amounts[]={0, 1, 2, 3, 4, 5, 10000, 10000000000000000000ull, 10203040506070809000ull, 123456789123456789};

TEST(ringct, d2h)
{
  key k, P1;
  skpkGen(k, P1);
  for (auto amount: test_amounts) {
    d2h(k, amount);
    ASSERT_TRUE(amount == h2d(k));
  }
}

TEST(ringct, d2b)
{
  for (auto amount: test_amounts) {
    bits b;
    d2b(b, amount);
    ASSERT_TRUE(amount == b2d(b));
  }
}

TEST(ringct, key_ostream)
{
  std::stringstream out;
  out << "BEGIN" << rct::H << "END";
  EXPECT_EQ(
    std::string{"BEGIN<8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94>END"},
    out.str()
  );
}

TEST(ringct, zeroCommmit)
{
  static const uint64_t amount = crypto::rand<uint64_t>();
  const rct::key z = rct::zeroCommit(amount);
  const rct::key a = rct::scalarmultBase(rct::identity());
  const rct::key b = rct::scalarmultH(rct::d2h(amount));
  const rct::key manual = rct::addKeys(a, b);
  ASSERT_EQ(z, manual);
}

static rct::key uncachedZeroCommit(uint64_t amount)
{
  const rct::key am = rct::d2h(amount);
  const rct::key bH = rct::scalarmultH(am);
  return rct::addKeys(rct::G, bH);
}

TEST(ringct, zeroCommitCache)
{
  ASSERT_EQ(rct::zeroCommit(0), uncachedZeroCommit(0));
  ASSERT_EQ(rct::zeroCommit(1), uncachedZeroCommit(1));
  ASSERT_EQ(rct::zeroCommit(2), uncachedZeroCommit(2));
  ASSERT_EQ(rct::zeroCommit(10), uncachedZeroCommit(10));
  ASSERT_EQ(rct::zeroCommit(200), uncachedZeroCommit(200));
  ASSERT_EQ(rct::zeroCommit(1000000000), uncachedZeroCommit(1000000000));
  ASSERT_EQ(rct::zeroCommit(3000000000000), uncachedZeroCommit(3000000000000));
  ASSERT_EQ(rct::zeroCommit(900000000000000), uncachedZeroCommit(900000000000000));
}

TEST(ringct, H)
{
  ge_p3 p3;
  ASSERT_EQ(ge_frombytes_vartime(&p3, rct::H.bytes), 0);
  ASSERT_EQ(memcmp(&p3, &ge_p3_H, sizeof(ge_p3)), 0);
}

TEST(ringct, mul8)
{
  ge_p3 p3;
  rct::key key;
  ASSERT_EQ(rct::scalarmult8(rct::identity()), rct::identity());
  rct::scalarmult8(p3,rct::identity());
  ge_p3_tobytes(key.bytes, &p3);
  ASSERT_EQ(key, rct::identity());
  ASSERT_EQ(rct::scalarmult8(rct::H), rct::scalarmultKey(rct::H, rct::EIGHT));
  rct::scalarmult8(p3,rct::H);
  ge_p3_tobytes(key.bytes, &p3);
  ASSERT_EQ(key, rct::scalarmultKey(rct::H, rct::EIGHT));
  ASSERT_EQ(rct::scalarmultKey(rct::scalarmultKey(rct::H, rct::INV_EIGHT), rct::EIGHT), rct::H);
}
