// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// DRS-E2 trace exporter — a HARVEST SHIM (docs/design/DRS_E2_REPLAY_DRIVER.md
// §1.3, §3.9, RD-Q2). Walks the C++ daemon's LMDB under ONE read snapshot
// and hands every byte to the Rust trace writer (shekyl_e2_trace_* in
// shekyl_ffi.h). The six passed-through facts and the cumulative difficulty
// are read from the record; the checkpoint is the daemon's own
// BlockchainLMDB::logical_state_digest_v0 (hashed in Rust through the
// FFI, over the same snapshot); the one value this file re-derives is the
// long-term effective median, and it says so below.
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
// a past chain with the present set and be wrong (RD-F18). To checkpoint
// several heights, export from several snapshots.
//
// The whole walk — the tip, every facts row, the checkpoint — runs inside
// one LMDB read transaction (db_rtxn_guard), the way the digest walker it
// must agree with holds one. A daemon still appending to the data
// directory cannot then move the tip between the facts and the checkpoint
// and make the trace carry a state no store ever held (a false DIVERGE).

#include <boost/filesystem.hpp>

#include <array>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>

#include "blockchain_db/blockchain_db.h"
#include "blockchain_db/lmdb/db_lmdb.h"
#include "common/command_line.h"
#include "cryptonote_config.h"
#include "cryptonote_core/blockchain.h"
#include "hardforks/hardforks.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_core/tx_pool.h"
#include "rolling_median.h"
#include "shekyl/shekyl_ffi.h"
#include "version.h"

#undef SHEKYL_DEFAULT_LOG_CATEGORY
#define SHEKYL_DEFAULT_LOG_CATEGORY "bcutil"

namespace po = boost::program_options;
using namespace cryptonote;

namespace {

// The long-term effective median IN FORCE FOR block h (S-CHAIN-R SCR-19):
// the median over the long-term weights of the recorded blocks below h —
// the last `window` of them — clamped at the full reward zone.
//
// LMDB stores no such row, and the daemon's own derivation
// (Blockchain::update_next_cumulative_weight_limit →
// get_long_term_block_weight_median) is private, cached at the current tip
// and O(window) per call, so this shim RE-DERIVES the value incrementally:
// the daemon's rolling-median type over the daemon's recorded long-term
// weights, with the daemon's clamp. It equals the daemon's number in every
// configuration a daemon can run — the window is the compile-time
// constant; the runtime override (`test_options->long_term_block_weight_window`)
// is set only by unit-test fixtures, never by a nettype. What the trace
// records is therefore a re-derivation by this shim, exported as a
// passed-through fact because no Rust rule derives SCR-19 yet; the field
// and this class leave together when one does (`ConnectFacts::DELETED_BY`).
//
// The window is walked once; `median_for(h)` is asked in ascending h and
// each answer is followed by `advance(h)` inserting block h's weight.
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

// `curve_tree_roots[h + 1]` as LMDB holds it. A missing row reads back as
// thirty-two zero bytes (get_curve_tree_root_at_height on MDB_NOTFOUND),
// and zero is never a root — the empty tree is the selene identity, not
// zero — so a zero here is a hole in the record, refused rather than
// exported as a fact the replay's CEN-B5 would then refuse at h + 1 and
// the grader would record as Rust disagreeing with a value LMDB never held.
bool root_after(const BlockchainDB& db, uint64_t h, std::array<uint8_t, 32>& out)
{
  out = db.get_curve_tree_root_at_height(h + 1);
  for (const uint8_t b : out)
    if (b != 0)
      return true;
  return false;
}

// What the command line asked for, resolved against the recorded tip.
struct export_range {
  uint64_t start;
  uint64_t stop;
  uint64_t tip;
};

// Walk `range` and write the trace at `out_path`; 0 on success. Runs
// entirely under the caller's read snapshot.
int export_trace(const BlockchainDB& db, const BlockchainLMDB& lmdb, const export_range& range, const std::string& out_path)
{
  writer_guard guard{shekyl_e2_trace_open(
      reinterpret_cast<const uint8_t*>(out_path.data()), out_path.size())};
  if (guard.w == nullptr)
  {
    LOG_ERROR("cannot open trace " << out_path);
    return 1;
  }

  LOG_PRINT_L0("Exporting facts for heights " << range.start << ".." << range.stop << " to " << out_path);
  effective_median_walker median(db, range.start);
  for (uint64_t h = range.start; h <= range.stop; ++h)
  {
    const difficulty_type cd = db.get_block_cumulative_difficulty(h);
    const uint64_t cd_lo = static_cast<uint64_t>(cd & std::numeric_limits<uint64_t>::max());
    const uint64_t cd_hi = static_cast<uint64_t>(cd >> 64);
    std::array<uint8_t, 32> root{};
    if (!root_after(db, h, root))
    {
      LOG_ERROR("curve_tree_roots[" << h + 1 << "] is absent or zero: the record has a hole; refusing to export it as a fact");
      return 1;
    }
    const int32_t rc = shekyl_e2_trace_push_facts(
        guard.w,
        h,
        static_cast<uint64_t>(db.get_block_weight(h)),
        db.get_block_long_term_weight(h),
        db.get_block_already_generated_coins(h),
        db.get_block_burn(h),
        root.data(),
        median.median_for(h),
        cd_lo,
        cd_hi);
    median.advance(h);
    if (rc != SHEKYL_E2_TRACE_OK)
    {
      LOG_ERROR("trace writer refused facts at height " << h << " (rc " << rc << ")");
      return 1;
    }
  }

  if (range.stop == range.tip)
  {
    // The daemon's own digest, over this same snapshot; hashed in Rust.
    const std::array<uint8_t, 32> digest = lmdb.logical_state_digest_v0();
    const int32_t rc = shekyl_e2_trace_push_checkpoint(guard.w, digest.data());
    if (rc != SHEKYL_E2_TRACE_OK)
    {
      LOG_ERROR("trace writer refused the checkpoint at the tip (rc " << rc << ")");
      return 1;
    }
    LOG_PRINT_L0("Checkpoint written after height " << range.tip);
  }
  else
  {
    LOG_PRINT_L0("No checkpoint: --block-stop " << range.stop << " is below the tip " << range.tip
                 << " and LMDB holds the spent set only as of the tip (RD-F18)");
  }

  guard.finished = true;
  const int32_t rc = shekyl_e2_trace_finish(guard.w);
  guard.w = nullptr;
  if (rc != SHEKYL_E2_TRACE_OK)
  {
    LOG_ERROR("trace writer failed to finish (rc " << rc << ")");
    return 1;
  }
  LOG_PRINT_L0("Done: " << out_path);
  return 0;
}

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
  const command_line::arg_descriptor<uint64_t> arg_block_stop = {"block-stop", "last height to export (default: the tip; a height above the tip is refused)", 0};

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
    std::cout << "Shekyl '" << SHEKYL_RELEASE_NAME << "' (v" << SHEKYL_VERSION_FULL << ")" << ENDL << ENDL;
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

  // The validator claims seeds on the mainnet schedule at every nettype and
  // reads no environment (RD-F19). A chain mined under a SEEDHASH_EPOCH_*
  // override is invisible as such in its own data under a fixed target, so
  // the one place the override can be seen is the environment it is set
  // in — this process's is the daemon's in the recipe that runs both from
  // one shell. First evidence, not proof: the recipe still states the
  // daemon's environment.
  if (shekyl_pow_randomx_v2_seed_epoch_overridden())
  {
    LOG_ERROR("SEEDHASH_EPOCH_* is set in this environment: a chain mined under a seed-epoch override is not one the validator's schedule can replay (RD-F19); unset it, and harvest only from a daemon that ran without it");
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
  // Absent means "the tip"; an explicit value means that value, zero
  // included (genesis alone), and is refused above the tip rather than
  // silently clamped to a height the caller did not name.
  const bool stop_given = !command_line::is_arg_defaulted(vm, arg_block_stop);
  const uint64_t block_stop_given = command_line::get_arg(vm, arg_block_stop);

  LOG_PRINT_L0("Initializing source blockchain (BlockchainDB), read-only");
  std::unique_ptr<Blockchain> core_storage;
  tx_memory_pool m_mempool(*core_storage);
  core_storage.reset(new Blockchain(m_mempool));
  // The LMDB backend by name: the checkpoint is BlockchainLMDB's own digest
  // walker, which the BlockchainDB interface does not carry.
  BlockchainLMDB* lmdb = new BlockchainLMDB();
  BlockchainDB* db = lmdb;
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

  int rc = 1;
  {
    // One snapshot for everything below (file header).
    db_rtxn_guard snapshot(db);

    const uint64_t height = db->height();
    if (height == 0)
    {
      LOG_ERROR("empty chain: nothing to export");
    }
    else
    {
      const uint64_t tip = height - 1;
      const uint64_t block_stop = stop_given ? block_stop_given : tip;
      if (block_stop > tip)
      {
        LOG_ERROR("--block-stop " << block_stop << " is past the tip " << tip);
      }
      else if (block_start > block_stop)
      {
        LOG_ERROR("--block-start " << block_start << " is past --block-stop " << block_stop);
      }
      else
      {
        rc = export_trace(*db, *lmdb, export_range{block_start, block_stop, tip}, out_path);
      }
    }
  }
  core_storage->deinit();
  return rc;

  CATCH_ENTRY("Export error", 1);
}
