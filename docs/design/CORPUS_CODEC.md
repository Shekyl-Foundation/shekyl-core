# The corpus codec (`shekyl-corpus`)

**Status: LIVING CONTRACT** — built in #1434 (`CF-4a` PR 2, merged
2026-11-19 as `f5e5cd7908`); last verified 2026-11-20 at
`dev@7a249e462c`, where the chain store's tests read the forged
shard-fill chain's corpus through it. Ruled by Rick, 2026-11-18: "Corpus
codec crate: yes, in its own PR under rule 26. Codec only: magic, version,
encode and decode. The five committed corpora must round-trip byte for
byte. Classify the crate in the production graph check."

## 1. Why the crate exists

The corpus is the artifact a chain is replayed from: every block with the
bodies of its listed transactions and its bundle section, as one versioned
file (`DRS_E2_REPLAY_DRIVER.md` RD-Q2, RD-F8, RD-F15). Its format was minted
in `shekyl-chain-ingest`'s `corpus.rs`, beside the replay `Source` that
reads it.

`CF-4a` (`CHAIN_FORGE.md` §12.1) replaces the checked-in shard-fill chain
with a forged one, hosted as a corpus. The chain store's tests are among
its readers: about fifty of them open a store over a prefix of that chain,
and they use the store's crate-private internals, so they live in
`shekyl-chain-store`. That crate cannot depend on `shekyl-chain-ingest`,
which depends on it. A second parser of the format in the store's tests is
not an option (rule 16: one serializer, shared by writer and reader). So
the format moves to a crate below both, and both read it through the same
code.

## 2. What it holds

- `CORPUS_MAGIC` and `CORPUS_FORMAT_VERSION` (layout 4).
- `CorpusWriter`: the one encoder. It verifies each record before it lands
  (RD-F15: the bodies match the block's listed hashes in count, order and
  hash, and each bundle body is its reference's) and patches the header's
  record count at `finish`.
- `CorpusReader`: the one decoder. `open` refuses a foreign magic, version
  or network tag; `next_record` yields `Record::Extend` (the parsed block,
  its bodies and its bundle section) or `Record::Rewind`, re-deriving every
  check the writer made.
- `CorpusFault`: every refusal of either side, by name.

Its dependencies are the wire types it parses (`shekyl-wire`), the header's
network tag (`shekyl-network`), heights and section references
(`shekyl-types`), and the bundle reference and body (`shekyl-archival-retention`).
Each is already a normal dependency of `shekyl-chain-ingest`, so the
lockfile gains only the crate itself.

## 3. What it refuses to hold

- **No `Source`, no events, no sequence numbers.** Turning records into
  the pipeline's `IngestEvent`s and `Candidate`s is the ingest's: its
  `corpus.rs` is now `CorpusSource`, a thin adapter over `CorpusReader`.
- **No store, no validator, no pipeline.** The codec parses and verifies a
  record's integrity; it never judges a block.
- **No second reader.** Every reader of a corpus, the replay and the
  store's tests alike, goes through `CorpusReader`.

## 4. Gates

- **The committed corpora round-trip byte for byte**
  (`shekyl-chain-ingest/tests/committed_corpora.rs`): the five replay
  vectors and every bench fixture corpus are decoded, written again from
  the parsed records, and compared with the committed bytes. The five
  vectors are named, so a missing one fails the test rather than
  shrinking it. It lives beside the corpora rather than in this crate so
  that both a regenerated corpus and a changed codec run it:
  `change_scope.py` scopes a change by its owning crate and that crate's
  dependents, and the ingest owns the files and depends on the codec.
- **The codec's refusals** (`src/tests.rs`): a foreign magic, version and
  network tag; a shortfall, a reorder and a padded blob on write; a
  tampered body, a crafted `tx_count`, a truncation, an unfinished file,
  bytes past the declared end, a height gap, an oversized length and
  height exhaustion on read; the rewind law on both sides; an unknown tag,
  `0x03` among them.
- **The ingest's adapter** (`shekyl-chain-ingest`'s `corpus_tests.rs`):
  records come out as sequenced events, a rewind as `IngestEvent::Rewind`,
  a bundle section on the candidate, and the codec's refusals unchanged.
- **The production graph** (`scripts/ci/shipped_graph.py`): the crate is
  in this repository's release graph through `shekyl-chain-ingest`, so it
  needs neither `HEADED_FOR_PRODUCTION` nor `NOT_SHIPPED`; `classify()`
  refuses a row for a crate already in the set.
- **Heights stay typed** (`scripts/ci/check_inland_height_u64.py`): the
  crate joins the gate's scope, so moving the format took none of its
  height sites out of the scan.
- **Rustdoc `-D warnings`** (`rust-audit-test.yml`): the crate docs state
  the layout, the one statement of the format a writer and a reader are
  held to.

## 5. Changing the format

A layout change bumps `CORPUS_FORMAT_VERSION` (rule 42's discipline), and
today's reader refuses every value but 4: an artifact is rebuilt, never
migrated (rule 15). `CF-3`'s layout 5 is the next such change
(`CHAIN_FORGE.md` §7.1), and it lands in this crate; which layouts its
reader accepts while layout-4 corpora remain is `CF-R7`'s ruling.

The record, the height cursor, the integrity checks, the writer and the
reader are separate modules. A new tag is a `Record` variant and the two
arms that encode and decode it. The cursor moves only for a tag that
moves the tip, so an offer — a block that does not extend the tip — does
not change the height law. The section-blob ceiling (`MAX_SECTION_BLOB`)
is the bundle-body packet ceiling; the ingest adapter's corpus tests hold
the two equal.
