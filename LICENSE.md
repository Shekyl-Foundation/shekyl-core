# Shekyl Licensing

This repository is licensed under the **BSD 3-Clause License**.

This includes both code derived from the Monero codebase and new code authored
for Shekyl. BSD 3-Clause was chosen for consistency with the upstream Monero
license and because it is well-suited to open-source cryptocurrency projects.

When redistributing this project, preserve all applicable license notices.

## 1) Shekyl License (BSD 3-Clause)

Copyright (c) 2024-2026, The Shekyl Foundation

All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## 2) Historical upstream attributions

This codebase contains code originally derived from the Monero project,
also licensed under BSD 3-Clause:

- Copyright (c) 2014-2022, The Monero Project
- Parts originally copyright (c) 2012-2013 The Cryptonote developers.
- Parts originally copyright (c) 2014 The Boolberry developers.

## 3) Vendored shekyl-oxide third-party crates

Consensus-critical FCMP++ dependencies are vendored under `rust/shekyl-oxide/`.
Their upstream project and snapshot metadata are tracked in:

- `rust/shekyl-oxide/UPSTREAM_MONERO_OXIDE_COMMIT`

Per-crate upstream license files are preserved in the vendored tree, including:

- `rust/shekyl-oxide/crypto/divisors/LICENSE`
- `rust/shekyl-oxide/crypto/helioselene/LICENSE`
- `rust/shekyl-oxide/crypto/generalized-bulletproofs/LICENSE`
- `rust/shekyl-oxide/crypto/fcmps/LICENSE`
- `rust/shekyl-oxide/crypto/fcmps/circuit-abstraction/LICENSE`
- `rust/shekyl-oxide/crypto/fcmps/ec-gadgets/LICENSE`
- `rust/shekyl-oxide/shekyl-oxide/io/LICENSE`
- `rust/shekyl-oxide/shekyl-oxide/generators/LICENSE`
- `rust/shekyl-oxide/shekyl-oxide/fcmp/fcmp++/LICENSE`
