# CHANGELOG entries waiting for the release cut

A pull request that owes a CHANGELOG entry (rule 95, "CHANGELOG scope")
adds it here as a new file. It does not edit `docs/CHANGELOG.md`.

An edit at the top of the `[Unreleased]` section conflicts with every
other open pull request that makes one. Each conflict evicts a pull
request from the merge queue and sends it back for a merge of `dev` and
a full CI run. A new file per pull request conflicts with nothing.

## Writing an entry

- **One file per pull request,** named after its branch with `/` written
  as `-`: branch `fix/tor-driver-spin` writes `fix-tor-driver-spin.md`.
  A later commit on the same branch edits that file.
- **The file holds the bullet or bullets** exactly as they will read in
  `docs/CHANGELOG.md`: `- **What changed.** Why, and what it means for
  whoever reads it.` No heading, no front matter.
- **No relative links.** The entry moves one directory up at the cut, so
  a relative link would break there. Name a document in backticks, as
  the CHANGELOG's entries already do: `NETWORK_IDENTITY.md` §2.4.1.

## At the release

`docs/RELEASING.md` step 1 moves every entry here into the release's
section of `docs/CHANGELOG.md`, newest merge first, and deletes the
files in the same commit. This README stays.
