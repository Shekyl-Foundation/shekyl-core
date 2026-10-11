#!/usr/bin/env bash
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Install the ProVerif that rust/shekyl-rpc-channel/model/run.py is pinned to,
# into a directory of the caller's choosing, without root.
#
# ONE RECIPE, HERE AND IN CI. The model's verdicts are pinned to one ProVerif
# version (run.py refuses any other). Two installs made two different ways
# can still differ in how they were built, so the developer's machine and the
# CI job both run this script and nothing else.
#
# WHY NOT `opam install proverif`. The opam package depends on lablgtk for
# ProVerif's interactive simulator, which needs the GTK 2 development headers
# from the system package manager, and so root. The model checker itself
# needs none of that. So opam supplies the pinned OCaml toolchain, and
# ProVerif is built from its own source release with `./build -nointeract`.
#
# Every download is checked against a SHA-256 recorded here before it is
# used.
#
# Usage:  install_proverif.sh PREFIX
# Result: PREFIX/proverif2.05/proverif   (add that directory to PATH)

set -euo pipefail

PREFIX="${1:?usage: install_proverif.sh PREFIX}"
PROVERIF_VERSION="2.05"
PROVERIF_URL="https://bblanche.gitlabpages.inria.fr/proverif/proverif${PROVERIF_VERSION}.tar.gz"
PROVERIF_SHA256="4871f53c32ab4a04669a060c4886ba5d9080496963fb980a9a62d2c429ceabc4"
OPAM_VERSION="2.3.0"
OPAM_URL="https://github.com/ocaml/opam/releases/download/${OPAM_VERSION}/opam-${OPAM_VERSION}-x86_64-linux"
OPAM_SHA256="324e78e3f33efeba279aacf9f9610cfec7b2df7d7e0e1640f75f09de85f96cc9"
OCAML_COMPILER="ocaml-base-compiler.4.14.2"
OCAMLFIND="ocamlfind.1.9.8"
OCAMLBUILD="ocamlbuild.0.16.1"

if [ "$(uname -s)-$(uname -m)" != "Linux-x86_64" ]; then
  echo "install_proverif.sh: this recipe pins an x86_64 Linux opam binary; got $(uname -s)-$(uname -m)" >&2
  exit 2
fi

# Absolute, because the steps below change directory.
mkdir -p "${PREFIX}"
PREFIX="$(cd "${PREFIX}" && pwd)"
BINARY="${PREFIX}/proverif${PROVERIF_VERSION}/proverif"
if [ -x "${BINARY}" ] && "${BINARY}" -help 2>&1 | grep -q "^Proverif ${PROVERIF_VERSION}\."; then
  echo "install_proverif.sh: ${BINARY} is already ProVerif ${PROVERIF_VERSION}"
  exit 0
fi

cd "${PREFIX}"

fetch() {
  # fetch URL SHA256 OUT -- download, then refuse the file unless it matches.
  local url="$1" want="$2" out="$3" got
  curl --fail --silent --show-error --location --max-time 300 --output "${out}.part" "${url}"
  got="$(sha256sum "${out}.part" | cut -d' ' -f1)"
  if [ "${got}" != "${want}" ]; then
    rm -f "${out}.part"
    echo "install_proverif.sh: ${url} has SHA-256 ${got}, expected ${want}" >&2
    exit 1
  fi
  mv "${out}.part" "${out}"
}

# The opam binary lives in bin/, apart from its root directory opam/.
mkdir -p bin
fetch "${OPAM_URL}" "${OPAM_SHA256}" bin/opam
chmod +x bin/opam
OPAM="${PREFIX}/bin/opam"

export OPAMROOT="${PREFIX}/opam"
export OPAMYES=1
export OPAMCOLOR=never
# Sandboxing needs bubblewrap and unprivileged user namespaces, which a CI
# container may not grant. The packages built are the pinned compiler and two
# build tools, fetched from the opam repository.
[ -d "${OPAMROOT}" ] || "${OPAM}" init --bare --no-setup --disable-sandboxing
"${OPAM}" switch list --short | grep -qx pv || "${OPAM}" switch create pv "${OCAML_COMPILER}"
"${OPAM}" install --switch pv "${OCAMLFIND}" "${OCAMLBUILD}"

fetch "${PROVERIF_URL}" "${PROVERIF_SHA256}" "proverif${PROVERIF_VERSION}.tar.gz"
rm -rf "proverif${PROVERIF_VERSION}"
tar -xzf "proverif${PROVERIF_VERSION}.tar.gz"
cd "proverif${PROVERIF_VERSION}"
eval "$("${OPAM}" env --switch pv --set-switch)"
./build -nointeract

if ! "${BINARY}" -help 2>&1 | grep -q "^Proverif ${PROVERIF_VERSION}\."; then
  echo "install_proverif.sh: the build did not produce ProVerif ${PROVERIF_VERSION} at ${BINARY}" >&2
  exit 1
fi
echo "install_proverif.sh: built ${BINARY}"
