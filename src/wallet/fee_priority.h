#pragma once

#include <stdint.h>
#include <string>
#include <array>
#include <algorithm>
#include <iterator>
#include <iosfwd>

#include <boost/optional/optional.hpp>

namespace tools
{
    enum class fee_priority : uint32_t
    {
        Default = 0,
        Unimportant, /* Low */
        Normal, /* Medium */
        Elevated, /* High */
        Priority, /* Very High */
    };

    std::ostream& operator<<(std::ostream& os, const fee_priority priority);

    namespace fee_priority_utilities
    {
        inline const std::array<std::string, 5>& fee_priority_strings()
        {
            static const std::array<std::string, 5> s = {{ "default", "unimportant", "normal", "elevated", "priority" }};
            return s;
        }

        inline const std::array<fee_priority, 5>& enums()
        {
            static const std::array<fee_priority, 5> e = {{ fee_priority::Default, fee_priority::Unimportant, fee_priority::Normal, fee_priority::Elevated, fee_priority::Priority }};
            return e;
        }

        inline fee_priority decrease(const fee_priority priority)
        {
            if (priority == fee_priority::Default)
            {
                return fee_priority::Default;
            }
            else
            {
                const uint32_t integralValue = static_cast<uint32_t>(priority);
                const auto decrementedIntegralValue = integralValue - 1u;
                return static_cast<fee_priority>(decrementedIntegralValue);
            }
        }

        inline constexpr uint32_t as_integral(const fee_priority priority)
        {
            return static_cast<uint32_t>(priority);
        }

        inline constexpr fee_priority from_integral(const uint32_t priority)
        {
            return (priority >= as_integral(fee_priority::Priority))
                ? fee_priority::Priority
                : static_cast<fee_priority>(priority);
        }

        inline bool is_valid(const uint32_t priority)
        {
            return priority <= as_integral(fee_priority::Priority);
        }

        inline fee_priority clamp(const fee_priority priority)
        {
            const auto highest = as_integral(fee_priority::Priority);
            const auto lowest = as_integral(fee_priority::Default);
            const auto current = as_integral(priority);

            if (current < lowest)
            {
                return fee_priority::Default;
            }
            else if (current > highest)
            {
                return fee_priority::Priority;
            }
            else
            {
                return priority;
            }
        }

        inline fee_priority clamp_modified(const fee_priority priority)
        {
            if (priority == fee_priority::Default)
            {
                return fee_priority::Unimportant;
            }
            else
            {
                return clamp(priority);
            }
        }

        inline const std::string& to_string(const fee_priority priority)
        {
            const auto integralValue = as_integral(clamp(priority));
            return fee_priority_strings().at(integralValue);
        }

        inline boost::optional<fee_priority> from_string(const std::string& str)
        {
            const auto& strings = fee_priority_strings();
            const auto strIterator = std::find(strings.begin(), strings.end(), str);
            if (strIterator == strings.end())
                return boost::none;

            const auto distance = std::distance(strings.begin(), strIterator);
            return enums().at(distance);
        }

    }
}
