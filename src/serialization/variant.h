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
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#pragma once

#include <variant>
#include <type_traits>
#include <cstddef>
#include "serialization.h"

template <class Archive, class T>
struct variant_serialization_traits
{
};

// Deserialize: read the tag, then scan alternatives via constexpr-if recursion
// to find the matching type and deserialize the payload.
template <template <bool> class Archive, typename Variant, size_t I = 0>
static bool variant_read(Archive<false> &ar, Variant &v,
                         typename Archive<false>::variant_tag_type t)
{
    if constexpr (I >= std::variant_size_v<Variant>) {
        ar.set_fail();
        return false;
    } else {
        using T = std::variant_alternative_t<I, Variant>;
        if (variant_serialization_traits<Archive<false>, T>::get_tag() == t) {
            T x{};
            if (!do_serialize(ar, x))
            {
                ar.set_fail();
                return false;
            }
            v = std::move(x);
            return true;
        }
        return variant_read<Archive, Variant, I + 1>(ar, v, t);
    }
}

template <template <bool> class Archive, typename... T>
static bool do_serialize(Archive<false> &ar, std::variant<T...> &v)
{
    typename Archive<false>::variant_tag_type t;
    ar.begin_variant();
    ar.read_variant_tag(t);
    if (!variant_read<Archive, std::variant<T...>>(ar, v, t))
    {
        ar.set_fail();
        return false;
    }
    ar.end_variant();
    return true;
}

// Serialize: visit the active alternative, write its tag, then serialize
// the payload.
template <template <bool> class Archive, typename... T>
static bool do_serialize(Archive<true> &ar, std::variant<T...> &v)
{
    return std::visit([&ar](auto &rv) -> bool {
        using U = std::decay_t<decltype(rv)>;
        ar.begin_variant();
        ar.write_variant_tag(variant_serialization_traits<Archive<true>, U>::get_tag());
        if (!do_serialize(ar, rv))
        {
            ar.set_fail();
            return false;
        }
        ar.end_variant();
        return true;
    }, v);
}
