
#include "net/net_utils_base.h"

#include <boost/uuid/uuid_io.hpp>

#include "string_tools.h"
#include "net/local_ip.h"

static inline uint32_t make_address_v4_from_v6(const boost::asio::ip::address_v6& a)
{
  const auto &bytes = a.to_bytes();
  uint32_t v4 = 0;
  v4 = (v4 << 8) | bytes[12];
  v4 = (v4 << 8) | bytes[13];
  v4 = (v4 << 8) | bytes[14];
  v4 = (v4 << 8) | bytes[15];
  return htonl(v4);
}

namespace epee { namespace net_utils
{
	bool ipv4_network_address::equal(const ipv4_network_address& other) const noexcept
	{ return is_same_host(other) && port() == other.port(); }

	bool ipv4_network_address::less(const ipv4_network_address& other) const noexcept
	{ return is_same_host(other) ? port() < other.port() : ip() < other.ip(); }

	std::string ipv4_network_address::str() const
	{ return string_tools::get_ip_string_from_int32(ip()) + ":" + std::to_string(port()); }

	std::string ipv4_network_address::host_str() const { return string_tools::get_ip_string_from_int32(ip()); }
	bool ipv4_network_address::is_loopback() const { return net_utils::is_ip_loopback(ip()); }
	bool ipv4_network_address::is_local() const { return net_utils::is_ip_local(ip()); }

	bool ipv6_network_address::equal(const ipv6_network_address& other) const noexcept
	{ return is_same_host(other) && port() == other.port(); }

	bool ipv6_network_address::less(const ipv6_network_address& other) const noexcept
	{ return is_same_host(other) ? port() < other.port() : m_address < other.m_address; }

	std::string ipv6_network_address::str() const
	{ return std::string("[") + host_str() + "]:" + std::to_string(port()); }

	std::string ipv6_network_address::host_str() const { return m_address.to_string(); }
	bool ipv6_network_address::is_loopback() const { return m_address.is_loopback(); }
	bool ipv6_network_address::is_local() const { return m_address.is_link_local(); }


	bool ipv4_network_subnet::equal(const ipv4_network_subnet& other) const noexcept
	{ return is_same_host(other) && m_mask == other.m_mask; }

	bool ipv4_network_subnet::less(const ipv4_network_subnet& other) const noexcept
	{ return subnet() < other.subnet() ? true : (other.subnet() < subnet() ? false : (m_mask < other.m_mask)); }

	std::string ipv4_network_subnet::str() const
	{ return string_tools::get_ip_string_from_int32(subnet()) + "/" + std::to_string(m_mask); }

	std::string ipv4_network_subnet::host_str() const { return string_tools::get_ip_string_from_int32(subnet()) + "/" + std::to_string(m_mask); }
	bool ipv4_network_subnet::is_loopback() const { return net_utils::is_ip_loopback(subnet()); }
	bool ipv4_network_subnet::is_local() const { return net_utils::is_ip_local(subnet()); }
	bool ipv4_network_subnet::matches(const ipv4_network_address &address) const
	{
		return (address.ip() & ~(0xffffffffull << m_mask)) == subnet();
	}


	bool network_address::equal(const network_address& other) const
	{
		// clang typeid workaround
		network_address::interface const* const self_ = self.get();
		network_address::interface const* const other_self = other.self.get();
		if (self_ == other_self) return true;
		if (!self_ || !other_self) return false;
		if (typeid(*self_) != typeid(*other_self)) return false;
		return self_->equal(*other_self);
	}

	bool network_address::less(const network_address& other) const
	{
		// clang typeid workaround
		network_address::interface const* const self_ = self.get();
		network_address::interface const* const other_self = other.self.get();
		if (self_ == other_self) return false;
		if (!self_ || !other_self) return self == nullptr;
		if (typeid(*self_) != typeid(*other_self))
			return self_->get_type_id() < other_self->get_type_id();
		return self_->less(*other_self);
	}

	namespace
	{
		//! \brief Does this address name a host at all?
		//!
		//! Anonymity zones hand every inbound connection the same per-zone
		//! `unknown()` sentinel (`net_node.inl` `set_default_remote`, one call
		//! per zone), so an address-keyed operation that equates two of them
		//! selects the whole zone rather than one peer.
		//!
		//! Spelled over `is_blockable()`, which is already exactly this test
		//! wherever it is used, but named separately: `is_blockable` asks a
		//! policy question ("may we ban this?") and this asks a semantic one
		//! ("does this denote a host?"). Coextensive today; if they diverge,
		//! this is the one line to change.
		//!
		//! DELETE this, the guard in `is_same_host`, and both comments once an
		//! inbound anonymity-zone connection carries a dial-verified endpoint:
		//! there is then no `unknown()` to compare and this is dead code.
		bool identifies_a_host(const network_address& addr)
		{
			return addr.is_blockable();
		}
	}

	bool network_address::is_same_host(const network_address& other) const
	{
		// clang typeid workaround
		network_address::interface const* const self_ = self.get();
		network_address::interface const* const other_self = other.self.get();
		// Two default-constructed addresses: the inherited contract calls these
		// the same host, and that is unchanged.
		if (!self_ && !other_self) return true;
		if (!self_ || !other_self) return false;
		// An address that names no host is not the same host as anything,
		// including another such address.
		//
		// MUST PRECEDE THE POINTER-EQUALITY SHORT-CIRCUIT BELOW. `self` is a
		// `shared_ptr`, and every inbound connection in an anonymity zone is
		// assigned its remote from the zone's single `default_remote`, so in
		// production they all alias one pointee. Placed after `self_ ==
		// other_self` this guard is dead in exactly the case it exists for, and
		// a test that builds two separate `unknown()` values still passes.
		if (!identifies_a_host(*this) || !identifies_a_host(other)) return false;
		if (self_ == other_self) return true;
		if (typeid(*self_) == typeid(*other_self))
			return self_->is_same_host(*other_self);
		const auto this_id = get_type_id();
		if (this_id == ipv4_network_address::get_type_id() && other.get_type_id() == ipv6_network_address::get_type_id())
		{
			const boost::asio::ip::address_v6 &actual_ip = other.as<const epee::net_utils::ipv6_network_address>().ip();
			if (actual_ip.is_v4_mapped())
			{
				const uint32_t v4ip = make_address_v4_from_v6(actual_ip);
				return is_same_host(ipv4_network_address(v4ip, 0));
			}
		}
		else if (this_id == ipv6_network_address::get_type_id() && other.get_type_id() == ipv4_network_address::get_type_id())
		{
			const boost::asio::ip::address_v6 &actual_ip = this->as<const epee::net_utils::ipv6_network_address>().ip();
			if (actual_ip.is_v4_mapped())
			{
				const uint32_t v4ip = make_address_v4_from_v6(actual_ip);
				return other.is_same_host(ipv4_network_address(v4ip, 0));
			}
		}
		return false;
	}

  std::string print_connection_context(const connection_context_base& ctx)
  {
    std::stringstream ss;
    ss << ctx.m_remote_address.str() << " " << ctx.m_connection_id << (ctx.m_is_income ? " INC":" OUT");
    return ss.str();
  }

  std::string print_connection_context_short(const connection_context_base& ctx)
  {
    std::stringstream ss;
    ss << ctx.m_remote_address.str() << (ctx.m_is_income ? " INC":" OUT");
    return ss.str();
  }

  const char* zone_to_string(zone value) noexcept
  {
    switch (value)
    {
    case zone::public_:
      return "public";
    case zone::i2p:
      return "i2p";
    case zone::tor:
      return "tor";
    default:
      break;
    }
    return "invalid";
  }

  zone zone_from_string(const boost::string_ref value) noexcept
  {
    if (value == "public")
      return zone::public_;
    if (value == "i2p")
      return zone::i2p;
    if (value == "tor")
      return zone::tor;
    return zone::invalid;
  }
}}

