// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// DRS-E2 trace exporter — a HARVEST SHIM (docs/design/DRS_E2_REPLAY_DRIVER.md
// §1.3, §3.9, RD-Q2). Walks the C++ daemon's LMDB and hands every byte to
// the Rust trace writer (shekyl_e2_trace_* in shekyl_ffi.h). It computes
// nothing the Rust side could compute: the six passed-through facts and the
// cumulative difficulty are read from the record; the long-term effective
// median is the daemon's own function, called exactly as add_block called
// it (blockchain.cpp update_next_cumulative_weight_limit); the checkpoint's
// digest is hashed in Rust from the families this walks.
//
// This file, its CMake target and the FFI it calls are deleted in the same
// commit that deletes the daemon. Nobody improves it into something with a
// future. Build: -DBUILD_E2_TRACE_EXPORT=ON (off by default; the daemon
// build does not need it).
//
// Usage:
//   shekyl-e2-trace-export --data-dir <dir> [--testnet|--stagenet|--regtest]
//       --out <trace file> [--block-start H] [--block-stop H]
//
// One checkpoint is written, after the last exported height, and only when
// that height is the recorded tip: LMDB holds the spent-key set as of NOW,
// not as of any past height, so a checkpoint at a non-tip height would pair
// a past chain with the present set and be wrong (RD-F16). To checkpoint
// several heights, export from several snapshots.

#include <boost/filesystem.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

#include "blockchain_db/blockchain_db.h"
#include "common/command_line.h"
#include "cryptonote_config.h"
#include "cryptonote_core/blockchain.h"
#include "hardforks/hardforks.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_core/tx_pool.h"
#include "rolling_median.h"
#include "shekyl/shekyl_ffi.h"
#include "version.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "bcutil"

namespace po = boost::program_options;
using namespace cryptonote;

namespace {

// The long-term effective median IN FORCE FOR block h (S-CHAIN-R SCR-19):
// the median over the long-term weights of the recorded blocks below h —
// the last `window` of them — clamped at the full reward zone, exactly as
// add_block derived it when the chain height was h
// (Blockchain::update_next_cumulative_weight_limit →
// get_long_term_block_weight_median, which is private and cached; this is
// its uncached body run incrementally: the daemon's own rolling-median
// type over the daemon's own recorded weights, so what is exported is what
// C++ said, not something this shim decided). The window is walked once;
// `median_for(h)` is asked in ascending h and each answer is followed by
// `advance(h)` inserting block h's weight.
class effective_median_walker {
public:
  explicit effective_median_walker(const BlockchainDB& db, uint64_t first_height)
    : m_db(db), m_median(CRYPTONOTE_LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE), m_next(0)
  {
    // Warm the window with the weights below first_height, at most one window's worth.
    const uint64_t window = CRYPTONOTE_LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE;
    const uint64_t from = first_height > window ? first_height - window : 0;
    for (uint64_t h = from; h < first_height; ++h)
      advance(h);
    m_next = first_height;
  }

  // The value in force for h; requires every height below h to have been advanced over.
  uint64_t median_for(uint64_t h) const
  {
    if (h != m_next)
      throw std::logic_error("effective_median_walker: heights must be asked in order");
    const uint64_t long_term_median = m_median.size() > 0
        ? m_median.median()
        : CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5;
    return std::max<uint64_t>(CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5, long_term_median);
  }

  void advance(uint64_t h)
  {
    m_median.insert(m_db.get_block_long_term_weight(h));
    m_next = h + 1;
  }

private:
  const BlockchainDB& m_db;
  epee::misc_utils::rolling_median_t<uint64_t> m_median;
  uint64_t m_next;
};

struct writer_guard {
  ShekylE2TraceWriter* w;
  bool finished = false;
  ~writer_guard()
  {
    if (w != nullptr && !finished)
      shekyl_e2_trace_abort(w);
  }
};

} // namespace

int main(int argc, char* argv[])
{
  TRY_ENTRY();

  epee::string_tools::set_module_name_and_folder(argv[0]);
  tools::on_startup();

  po::options_description desc_cmd_only("Command line options");
  po::options_description desc_cmd_sett("Command line options and settings options");
  const command_line::arg_descriptor<std::string> arg_log_level = {"log-level", "0-4 or categories", ""};
  const command_line::arg_descriptor<std::string> arg_out = {"out", "trace file to write", ""};
  const command_line::arg_descriptor<uint64_t> arg_block_start = {"block-start", "first height to export", 0};
  const command_line::arg_descriptor<uint64_t> arg_block_stop = {"block-stop", "last height to export (default: the tip)", 0};

  command_line::add_arg(desc_cmd_only, command_line::arg_help);
  command_line::add_arg(desc_cmd_sett, cryptonote::arg_data_dir);
  command_line::add_arg(desc_cmd_sett, cryptonote::arg_testnet_on);
  command_line::add_arg(desc_cmd_sett, cryptonote::arg_stagenet_on);
  command_line::add_arg(desc_cmd_sett, cryptonote::arg_regtest_on);
  command_line::add_arg(desc_cmd_sett, arg_log_level);
  command_line::add_arg(desc_cmd_sett, arg_out);
  command_line::add_arg(desc_cmd_sett, arg_block_start);
  command_line::add_arg(desc_cmd_sett, arg_block_stop);

  po::options_description desc_options("Allowed options");
  desc_options.add(desc_cmd_only).add(desc_cmd_sett);

  po::variables_map vm;
  const bool parsed = command_line::handle_error_helper(desc_options, [&]() {
    auto parser = po::command_line_parser(argc, argv).options(desc_options);
    po::store(parser.run(), vm);
    po::notify(vm);
    return true;
  });
  if (!parsed)
    return 1;

  if (command_line::get_arg(vm, command_line::arg_help))
  {
    std::cout << "Shekyl '" << MONERO_RELEASE_NAME << "' (v" << MONERO_VERSION_FULL << ")" << ENDL << ENDL;
    std::cout << desc_options << std::endl;
    return 1;
  }

  mlog_configure(mlog_get_default_log_path("shekyl-e2-trace-export.log"), true);
  if (!command_line::is_arg_defaulted(vm, arg_log_level))
    mlog_set_log(command_line::get_arg(vm, arg_log_level).c_str());
  else
    mlog_set_log("0,bcutil:INFO");

  const std::string out_path = command_line::get_arg(vm, arg_out);
  if (out_path.empty())
  {
    LOG_ERROR("--out is required");
    return 1;
  }

  const bool opt_testnet = command_line::get_arg(vm, cryptonote::arg_testnet_on);
  const bool opt_stagenet = command_line::get_arg(vm, cryptonote::arg_stagenet_on);
  // The daemon's own flag: a regtest chain lives under <data-dir>/fake, its
  // nettype is FAKECHAIN, and Blockchain::init wants the regtest
  // test_options the daemon hands it (cryptonote_core.cpp, core::init).
  const bool opt_regtest = command_line::get_arg(vm, cryptonote::arg_regtest_on);
  if (opt_regtest && (opt_testnet || opt_stagenet))
  {
    LOG_ERROR("--regtest excludes --testnet / --stagenet");
    return 1;
  }
  const network_type net_type = opt_regtest ? FAKECHAIN : opt_testnet ? TESTNET : opt_stagenet ? STAGENET : MAINNET;
  boost::filesystem::path data_dir(command_line::get_arg(vm, cryptonote::arg_data_dir));
  if (opt_regtest)
    data_dir /= "fake";
  const std::string opt_data_dir = data_dir.string();
  const uint64_t block_start = command_line::get_arg(vm, arg_block_start);
  uint64_t block_stop = command_line::get_arg(vm, arg_block_stop);

  LOG_PRINT_L0("Initializing source blockchain (BlockchainDB), read-only");
  std::unique_ptr<Blockchain> core_storage;
  tx_memory_pool m_mempool(*core_storage);
  core_storage.reset(new Blockchain(m_mempool));
  BlockchainDB* db = new_db();
  if (db == nullptr)
  {
    LOG_ERROR("Failed to initialize a database");
    return 1;
  }
  const std::string filename = (boost::filesystem::path(opt_data_dir) / db->get_db_name()).string();
  LOG_PRINT_L0("Loading blockchain from folder " << filename << " ...");
  try
  {
    db->open(filename, DBF_RDONLY);
  }
  catch (const std::exception& e)
  {
    LOG_ERROR("Error opening database: " << e.what());
    return 1;
  }
  const std::pair<uint8_t, uint64_t> regtest_hard_forks[3] = {
    std::make_pair(1, 0),
    std::make_pair(mainnet_hard_forks[num_mainnet_hard_forks - 1].version, 1),
    std::make_pair(0, 0)};
  const cryptonote::test_options regtest_test_options = {regtest_hard_forks, 0};
  if (!core_storage->init(db, net_type, /*offline=*/true, opt_regtest ? &regtest_test_options : nullptr))
  {
    LOG_ERROR("Failed to initialize source blockchain storage");
    return 1;
  }

  const uint64_t height = db->height();
  if (height == 0)
  {
    LOG_ERROR("empty chain: nothing to export");
    core_storage->deinit();
    return 1;
  }
  const uint64_t tip = height - 1;
  if (block_stop == 0 || block_stop > tip)
    block_stop = tip;
  if (block_start > block_stop)
  {
    LOG_ERROR("--block-start " << block_start << " is past --block-stop " << block_stop);
    core_storage->deinit();
    return 1;
  }

  writer_guard guard{shekyl_e2_trace_open(
      reinterpret_cast<const uint8_t*>(out_path.data()), out_path.size())};
  if (guard.w == nullptr)
  {
    LOG_ERROR("cannot open trace " << out_path);
    core_storage->deinit();
    return 1;
  }

  LOG_PRINT_L0("Exporting facts for heights " << block_start << ".." << block_stop << " to " << out_path);
  effective_median_walker median(*db, block_start);
  for (uint64_t h = block_start; h <= block_stop; ++h)
  {
    const difficulty_type cd = db->get_block_cumulative_difficulty(h);
    const uint64_t cd_lo = static_cast<uint64_t>(cd & std::numeric_limits<uint64_t>::max());
    const uint64_t cd_hi = static_cast<uint64_t>(cd >> 64);
    const std::array<uint8_t, 32> root_after = db->get_curve_tree_root_at_height(h + 1);
    const int32_t rc = shekyl_e2_trace_push_facts(
        guard.w,
        h,
        static_cast<uint64_t>(db->get_block_weight(h)),
        db->get_block_long_term_weight(h),
        db->get_block_already_generated_coins(h),
        db->get_block_burn(h),
        root_after.data(),
        median.median_for(h),
        cd_lo,
        cd_hi);
    median.advance(h);
    if (rc != SHEKYL_E2_TRACE_OK)
    {
      LOG_ERROR("trace writer refused facts at height " << h << " (rc " << rc << ")");
      core_storage->deinit();
      return 1;
    }
  }

  if (block_stop == tip)
  {
    // The families as of NOW, which is the tip: height-ordered hashes, the
    // whole spent set, the live root. Hashed in Rust.
    if (height > std::numeric_limits<size_t>::max() / 32)
    {
      LOG_ERROR("block count overflows size_t");
      core_storage->deinit();
      return 1;
    }
    std::vector<uint8_t> hashes(static_cast<size_t>(height) * 32);
    for (uint64_t h = 0; h < height; ++h)
    {
      const crypto::hash id = db->get_block_hash_from_height(h);
      std::memcpy(hashes.data() + static_cast<size_t>(h) * 32, &id, 32);
    }
    std::vector<uint8_t> spent;
    uint64_t n_spent = 0;
    db->for_all_key_images([&](const crypto::key_image& ki) {
      const size_t off = spent.size();
      spent.resize(off + 32);
      std::memcpy(spent.data() + off, &ki, 32);
      ++n_spent;
      return true;
    });
    const std::array<uint8_t, 32> live_root = db->get_curve_tree_root();
    const int32_t rc = shekyl_e2_trace_push_checkpoint(
        guard.w,
        hashes.data(),
        height,
        n_spent == 0 ? nullptr : spent.data(),
        n_spent,
        live_root.data());
    if (rc != SHEKYL_E2_TRACE_OK)
    {
      LOG_ERROR("trace writer refused the checkpoint at the tip (rc " << rc << ")");
      core_storage->deinit();
      return 1;
    }
    LOG_PRINT_L0("Checkpoint written after height " << tip << " (" << height << " blocks, " << n_spent << " spent keys)");
  }
  else
  {
    LOG_PRINT_L0("No checkpoint: --block-stop " << block_stop << " is below the tip " << tip
                 << " and LMDB holds the spent set only as of the tip (RD-F16)");
  }

  guard.finished = true;
  const int32_t rc = shekyl_e2_trace_finish(guard.w);
  guard.w = nullptr;
  core_storage->deinit();
  if (rc != SHEKYL_E2_TRACE_OK)
  {
    LOG_ERROR("trace writer failed to finish (rc " << rc << ")");
    return 1;
  }
  LOG_PRINT_L0("Done: " << out_path);
  return 0;

  CATCH_ENTRY("Export error", 1);
}
