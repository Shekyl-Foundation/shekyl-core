# Shekyl Licensing

This repository contains code derived from the Monero codebase and new code authored for Shekyl.

Licensing is therefore split by provenance:

- **Upstream-derived Monero code** remains under the Monero BSD 3-Clause license.
- **Shekyl-authored additions and modifications** are licensed under the MIT License, unless a file or directory states otherwise.

When redistributing this project, preserve all applicable license notices.

## 1) Upstream Monero License (BSD 3-Clause)

Copyright (c) 2014-2022, The Monero Project

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

Historical upstream attributions retained in this codebase:

- Parts originally copyright (c) 2012-2013 The Cryptonote developers.
- Parts originally copyright (c) 2014 The Boolberry developers.

## 2) Shekyl License (MIT)

Copyright (c) 2026 Shekyl contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

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
