// Copyright (c) 2017-2022, The Monero Project
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

#pragma once

#include "crypto/crypto.h"
#include "fcmp/ct_types.h"
#include "cryptonote_config.h"


// Hardware-wallet backends are not in this tree. See docs/HARDWARE_WALLETS.md.

namespace hw {

    // Software key helper. Hardware onboarding, transaction sessions, and the
    // FCMP offload hooks left with the Ledger and Trezor backends
    // (docs/HARDWARE_WALLETS.md). Miner-transaction key generation and the
    // device unit tests call what remains.
    class device {
    protected:
        std::string  name;

    public:

        device() {}
        virtual ~device() {}

        virtual bool set_name(const std::string &name) = 0;
        virtual const std::string get_name() const = 0;

        virtual bool  scalarmultKey(ct::key & aP, const ct::key &P, const ct::key &a) = 0;
        virtual bool  scalarmultBase(ct::key &aG, const ct::key &a) = 0;
        virtual bool  sc_secret_add( crypto::secret_key &r, const crypto::secret_key &a, const crypto::secret_key &b) = 0;
        virtual crypto::secret_key  generate_keys(crypto::public_key &pub, crypto::secret_key &sec, const crypto::secret_key& recovery_key = crypto::secret_key(), bool recover = false) = 0;
        virtual bool  generate_key_derivation(const crypto::public_key &pub, const crypto::secret_key &sec, crypto::key_derivation &derivation) = 0;
        virtual bool  secret_key_to_public_key(const crypto::secret_key &sec, crypto::public_key &pub) = 0;
        virtual bool  generate_key_image(const crypto::public_key &pub, const crypto::secret_key &sec, crypto::key_image &image) = 0;
    };

    class device_registry {
    private:
      std::map<std::string, std::unique_ptr<device>> registry;

    public:
      device_registry();
      bool register_device(const std::string & device_name, device * hw_device);
      device& get_device(const std::string & device_descriptor);
    };

    device& get_device(const std::string & device_descriptor);
    bool register_device(const std::string & device_name, device * hw_device);
}

