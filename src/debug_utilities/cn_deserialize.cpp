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

#include <filesystem>
#include <boost/algorithm/string/join.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_core/blockchain.h"
#include "common/command_line.h"
#include "version.h"

#undef SHEKYL_DEFAULT_LOG_CATEGORY
#define SHEKYL_DEFAULT_LOG_CATEGORY "debugtools.deserialize"

namespace po = boost::program_options;
using namespace epee;

using namespace cryptonote;

int main(int argc, char* argv[])
{
  uint32_t log_level = 0;
  std::string input;

  tools::on_startup();

  std::filesystem::path output_file_path;

  po::options_description desc_cmd_only("Command line options");
  po::options_description desc_cmd_sett("Command line options and settings options");
  const command_line::arg_descriptor<uint32_t> arg_log_level  = {"log-level",  "", log_level};
  const command_line::arg_descriptor<std::string> arg_input = {"input", "Specify input has a hexadecimal string", ""};

  command_line::add_arg(desc_cmd_sett, arg_log_level);
  command_line::add_arg(desc_cmd_sett, arg_input);

  command_line::add_arg(desc_cmd_only, command_line::arg_help);

  po::options_description desc_options("Allowed options");
  desc_options.add(desc_cmd_only).add(desc_cmd_sett);

  po::variables_map vm;
  bool r = command_line::handle_error_helper(desc_options, [&]()
  {
    po::store(po::parse_command_line(argc, argv, desc_options), vm);
    po::notify(vm);
    return true;
  });
  if (! r)
    return 1;

  if (command_line::get_arg(vm, command_line::arg_help))
  {
    std::cout << "Shekyl '" << MONERO_RELEASE_NAME << "' (v" << MONERO_VERSION_FULL << ")" << ENDL << ENDL;
    std::cout << desc_options << std::endl;
    return 1;
  }

  log_level    = command_line::get_arg(vm, arg_log_level);
  input        = command_line::get_arg(vm, arg_input);
  if (input.empty())
  {
    std::cerr << "--input is mandatory" << std::endl;
    return 1;
  }

  mlog_configure("", true);

  cryptonote::blobdata blob;
  if (!epee::string_tools::parse_hexstr_to_binbuff(input, blob))
  {
    std::cerr << "Invalid hex input" << std::endl;
    return 1;
  }

  // tx_extra is printed as the raw bytes inside the JSON; the field-level
  // pretty-printer left with the C++ tx_extra parser (TX_EXTRA_RUST_CUTOVER.md
  // §4). The codec is shekyl-wire's; decode an extra with it, not here.
  cryptonote::block block;
  cryptonote::transaction tx;
  if (cryptonote::parse_and_validate_block_from_blob(blob, block))
  {
    std::cout << "Parsed block:" << std::endl;
    std::cout << cryptonote::obj_to_json_str(block) << std::endl;
  }
  else if (cryptonote::parse_and_validate_tx_from_blob(blob, tx) || cryptonote::parse_and_validate_tx_base_from_blob(blob, tx))
  {
    if (tx.pruned)
      std::cout << "Parsed pruned transaction:" << std::endl;
    else
      std::cout << "Parsed transaction:" << std::endl;
    std::cout << cryptonote::obj_to_json_str(tx) << std::endl;
  }
  else
  {
    std::cerr << "Not a recognized CN type" << std::endl;
    return 1;
  }



  return 0;
}
