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
#include "gtest/gtest.h"
#include "common/command_line.h"
#include "common/removed_flags.h"
#include <sstream>

TEST(CommandLine, IsYes)
{
  EXPECT_TRUE(command_line::is_yes("Y"));
  EXPECT_TRUE(command_line::is_yes("y"));
  EXPECT_TRUE(command_line::is_yes("YES"));
  EXPECT_TRUE(command_line::is_yes("YEs"));
  EXPECT_TRUE(command_line::is_yes("YeS"));
  EXPECT_TRUE(command_line::is_yes("yES"));
  EXPECT_TRUE(command_line::is_yes("Yes"));
  EXPECT_TRUE(command_line::is_yes("yeS"));
  EXPECT_TRUE(command_line::is_yes("yEs"));
  EXPECT_TRUE(command_line::is_yes("yes"));

  EXPECT_FALSE(command_line::is_yes(""));
  EXPECT_FALSE(command_line::is_yes("yes-"));
  EXPECT_FALSE(command_line::is_yes("NO"));
  EXPECT_FALSE(command_line::is_yes("No"));
  EXPECT_FALSE(command_line::is_yes("nO"));
  EXPECT_FALSE(command_line::is_yes("no"));
}

// A flag we delete does not stop existing for operators: it lives on in their
// config files and service units. `handle_removed_flag` is what turns the
// resulting "unrecognized option" into a migration instruction, and a removal
// that forgets to register there is a removal that strands whoever had it set.
//
// `--hide-my-port` is the case in hand. Our own fleet generator wrote
// `hide-my-port=1` into every node config until the same change that removed
// the flag, so the config-file spelling is not hypothetical -- and Boost hands
// the handler the whole `name=value` token, which is why the second limb
// matters as much as the first.
namespace
{
  struct captured_cerr
  {
    std::ostringstream sink;
    std::streambuf *saved{std::cerr.rdbuf(sink.rdbuf())};
    ~captured_cerr() { std::cerr.rdbuf(saved); }
  };

  std::string removed_flag_message(const char *token, bool &handled)
  {
    captured_cerr capture;
    handled = shekyl::cli::handle_removed_flag(
      boost::program_options::unknown_option(token), "shekyld");
    return capture.sink.str();
  }
}

TEST(removed_flags, hide_my_port_directs_the_operator_to_the_derived_replacement)
{
  for (const char *token : {"hide-my-port", "hide-my-port=1", "--hide-my-port"})
  {
    bool handled = false;
    const std::string msg = removed_flag_message(token, handled);
    EXPECT_TRUE(handled) << "unhandled token '" << token << "' leaves the operator "
                            "with a bare unrecognized-option error";
    EXPECT_NE(std::string::npos, msg.find("--in-peers 0"))
      << "the message must name the replacement, not just report the removal; got: " << msg;
  }
}

TEST(removed_flags, a_flag_that_was_never_removed_is_not_claimed)
{
  // Negative control. Without it the assertions above would also pass on a
  // handler that answered true for everything, which would swallow real
  // typos behind a migration message for a flag nobody removed.
  bool handled = true;
  const std::string msg = removed_flag_message("in-peers", handled);
  EXPECT_FALSE(handled) << "a live flag must fall through to the normal parse error";
  EXPECT_TRUE(msg.empty()) << "nothing should be printed for it; got: " << msg;
}
