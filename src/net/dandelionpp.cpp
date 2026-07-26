// Copyright (c) 2019-2022, The Monero Project
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

// RP-2a (docs/design/DAEMON_RELAY_PRIVACY.md §16): the stem-map logic — slot
// selection, source pinning, churn refill — moved to Rust
// (shekyl-relay-privacy's `StemMap`; see rust/shekyl-ffi/src/dandelionpp_ffi.rs).
// This class keeps its ABI so `levin_notify` and the `dandelionpp_map` gtests
// compile unchanged, and forwards to the FFI. Boost UUIDs are 16 contiguous
// bytes (`uint8_t data[16]`), so every crossing is a `reinterpret_cast`, not a
// copy. `out_mapping_` is a shadow of the Rust map's ordered slots that backs
// the iterator ABI; it is refreshed after every mutation. This wrapper is
// transitional and is removed at RP-3, when `levin_notify` itself ports.

#include "dandelionpp.h"

#include <cstdint>
#include <limits>

#include "common/expect.h"

namespace net
{
namespace dandelionpp
{
    connection_map::connection_map(std::vector<boost::uuids::uuid> out_connections, const std::size_t stems)
      : handle_(nullptr, &shekyl_dandelionpp_map_free),
        out_mapping_()
    {
        // Preserve the original contract: `select_stem` reserved max size_t as
        // its error sentinel, so the constructor rejected that stem count up
        // front. Keep the throw here rather than letting the Rust map abort on
        // the resulting allocation.
        if (stems == std::numeric_limits<std::size_t>::max())
            MONERO_THROW(common_error::kInvalidArgument, "stems value cannot be max size_t");

        handle_.reset(shekyl_dandelionpp_map_new(
            reinterpret_cast<const std::uint8_t*>(out_connections.data()),
            out_connections.size(),
            stems));
        refresh_shadow();
    }

    connection_map::connection_map(const connection_map& source)
      : handle_(shekyl_dandelionpp_map_clone(source.handle_.get()), &shekyl_dandelionpp_map_free),
        out_mapping_(source.out_mapping_)
    {}

    connection_map::~connection_map() noexcept
    {}

    void connection_map::refresh_shadow()
    {
        const std::size_t count = shekyl_dandelionpp_map_snapshot(handle_.get(), nullptr, 0);
        out_mapping_.resize(count);
        if (count != 0)
        {
            shekyl_dandelionpp_map_snapshot(
                handle_.get(),
                reinterpret_cast<std::uint8_t*>(out_mapping_.data()),
                count);
        }
    }

    connection_map connection_map::clone() const
    {
        return {*this};
    }

    bool connection_map::update(std::vector<boost::uuids::uuid> current)
    {
        const bool changed = shekyl_dandelionpp_map_update(
            handle_.get(),
            reinterpret_cast<const std::uint8_t*>(current.data()),
            current.size());
        // Slots may have been dropped, backfilled, or grown; resync the shadow.
        refresh_shadow();
        return changed;
    }

    std::size_t connection_map::size() const noexcept
    {
        return shekyl_dandelionpp_map_live_stems(handle_.get());
    }

    boost::uuids::uuid connection_map::get_stem(const boost::uuids::uuid& source)
    {
        // `get_stem` pins the source to a slot (mutating usage/in-mapping) but
        // never changes the slot set, so the shadow stays valid — no refresh.
        boost::uuids::uuid out{};
        shekyl_dandelionpp_map_get_stem(
            handle_.get(),
            reinterpret_cast<const std::uint8_t*>(&source),
            reinterpret_cast<std::uint8_t*>(&out));
        return out;
    }
} // dandelionpp
} // net
