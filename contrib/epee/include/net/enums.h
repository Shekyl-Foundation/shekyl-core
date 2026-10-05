// Copyright (c) 2018-2022, The Monero Project

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

#pragma once

#include <cstdint>
#include <optional>
#include <stdexcept>

namespace epee
{
namespace net_utils
{
	enum class address_type : std::uint8_t
	{
		// Do not change values, this will break serialization
		invalid = 0,
		ipv4 = 1,
		ipv6 = 2,
		tor = 4
	};

	//! Which connector carried a session, or which connector dials an address.
	//! Clearnet is 0 and Tor is 1, matching `ConnectorId` in
	//! `shekyl-transport-layer`. There is no value 2: the retired zone enum
	//! left that discriminant unused, and this type does not take it.
	enum class connector_id : std::uint8_t
	{
		clearnet = 0,
		tor = 1
	};

	//! Closed set, in `ConnectorId::ALL` order. A new connector is a member
	//! here in the same change that adds the enumerator.
	inline constexpr connector_id all_connectors[] = {
		connector_id::clearnet,
		connector_id::tor,
	};

	constexpr bool operator<(connector_id a, connector_id b) noexcept
	{
		return static_cast<std::uint8_t>(a) < static_cast<std::uint8_t>(b);
	}

	constexpr bool operator<=(connector_id a, connector_id b) noexcept
	{
		return static_cast<std::uint8_t>(a) <= static_cast<std::uint8_t>(b);
	}

	//! `0xff` and any other byte are unnamed.
	inline std::optional<connector_id> connector_from_byte(std::uint8_t raw) noexcept
	{
		switch (raw)
		{
		case static_cast<std::uint8_t>(connector_id::clearnet):
			return connector_id::clearnet;
		case static_cast<std::uint8_t>(connector_id::tor):
			return connector_id::tor;
		default:
			return std::nullopt;
		}
	}

	const char* connector_id_to_string(connector_id value) noexcept;

	inline connector_id require_session_connector(std::uint8_t raw)
	{
		if (const auto id = connector_from_byte(raw))
			return *id;
		throw std::logic_error{"session has no connector"};
	}
} // net_utils
} // epee

namespace std
{
	template<> struct hash<epee::net_utils::connector_id>
	{
		std::size_t operator()(const epee::net_utils::connector_id id) const
		{
			return static_cast<std::size_t>(id);
		}
	};
} // std
