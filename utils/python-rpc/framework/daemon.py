# Copyright (c) 2018-2022, The Monero Project

# 
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice, this list of
#    conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright notice, this list
#    of conditions and the following disclaimer in the documentation and/or other
#    materials provided with the distribution.
# 
# 3. Neither the name of the copyright holder nor the names of its contributors may be
#    used to endorse or promote products derived from this software without specific
#    prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
# THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""Daemon class to make rpc calls and store state.

Every call is one JSON-RPC 2.0 request to `/json_rpc`, named as the
daemon's method table names it (`INPUT_GRAMMAR.md` §17,
`docs/generated/rpc_wire_schema.tsv`). Bytes travel as base64: the
methods here take and give `bytes`. Heights are tip ordinals. A refusal
raises `framework.rpc.RpcRefusal`.
"""

import base64

from .rpc import JSONRPC

def b64(data):
    """`bytes` as the wire's base64."""
    return base64.b64encode(data).decode('ascii')

def unb64(text):
    """The wire's base64 as `bytes`."""
    return base64.b64decode(text, validate=True)

def selector(height = None, hash = None):
    """A block selector: exactly one of `height`, `hash`, or the tip."""
    if height is not None and hash is not None:
        raise ValueError('a selector names a height or a hash, not both')
    if height is not None:
        return {'height': height}
    if hash is not None:
        return {'hash': hash}
    return {'tip': None}

class Daemon(object):

    def __init__(self, protocol='http', host='127.0.0.1', port=0, idx=0, restricted_rpc = False):
        base = 18480 if restricted_rpc else 18180
        self.host = host
        self.port = port
        self.rpc = JSONRPC('{protocol}://{host}:{port}'.format(protocol=protocol, host=host, port=port if port else base+idx))

    def call(self, method, params = None):
        return self.rpc.call(method, params)

    # Chain reads.

    def version(self):
        return self.call('version')

    def chain_height(self):
        return self.call('chain_height')

    def block_header_show(self, height = None, hash = None, pow = False):
        params = selector(height, hash)
        if pow:
            params['pow'] = True
        return self.call('block_header_show', params)

    def block_header_list(self, from_height = None, to_height = None, hashes = None, pow = False):
        """Inclusive heights `from_height`..`to_height`, or a list of
        hashes. Each slot is a header, `{"missing": null}`, or `null`."""
        if hashes is not None:
            params = {'hash': list(hashes)}
        else:
            params = {'from': from_height, 'to': to_height}
        if pow:
            params['pow'] = True
        return self.call('block_header_list', params)

    def block_show(self, height = None, hash = None, pow = False, prune = False):
        params = selector(height, hash)
        if pow:
            params['pow'] = True
        if prune:
            params['prune'] = True
        return self.call('block_show', params)

    def block_list(self, heights, prune = False):
        params = {'height': list(heights)}
        if prune:
            params['prune'] = True
        return self.call('block_list', params)

    def tx_show(self, id, prune = False):
        params = {'id': id}
        if prune:
            params['prune'] = True
        return self.call('tx_show', params)

    def tx_list(self, ids, prune = False):
        params = {'id': list(ids)}
        if prune:
            params['prune'] = True
        return self.call('tx_list', params)

    def chain_spent(self, key_images):
        return self.call('chain_spent', {'key_image': list(key_images)})

    def fee(self):
        return self.call('fee')

    def chain_coinbase_sum(self, from_height, to_height):
        """The coinbase sum over the inclusive heights."""
        return self.call('chain_coinbase_sum', {'from': from_height, 'to': to_height})

    def chain_alt(self):
        return self.call('chain_alt')

    def curve_show(self, height = None):
        params = {'height': height} if height is not None else {'tip': None}
        return self.call('curve_show', params)

    def archival_claim_show(self, persona):
        return self.call('archival_claim_show', {'persona': persona})

    def shard_coverage(self):
        return self.call('shard_coverage')

    def shard_fetch(self, id):
        return self.call('shard_fetch', {'id': id})

    # Node state.

    def daemon_status(self):
        return self.call('daemon_status')

    def sync_status(self):
        return self.call('sync_status')

    def peer_connections(self):
        return self.call('peer_connections')

    def peer_list(self, local = False):
        return self.call('peer_list', {'local': True} if local else {})

    def p2p_stats(self):
        return self.call('p2p_stats')

    def relay_stats(self):
        return self.call('relay_stats')

    def option_set(self, values):
        """`option_set`: `values` maps option names to value text in the
        input grammar's syntax (RPC_CHANNEL.md 6.4); all or nothing."""
        return self.call('option_set', {'value': dict(values)})

    def option_show(self, names = None):
        """`option_show`: every row the caller may see, or the named rows."""
        return self.call('option_show', {} if names is None else {'name': list(names)})

    def daemon_stop(self):
        return self.call('daemon_stop')

    # The pool.

    def txpool_list(self):
        return self.call('txpool_list')

    def txpool_stats(self):
        return self.call('txpool_stats')

    def txpool_flush(self, ids = None):
        return self.call('txpool_flush', {} if ids is None else {'id': list(ids)})

    def tx_relay(self, ids):
        return self.call('tx_relay', {'id': list(ids)})

    def tx_submit(self, body):
        """The submit verdict (DAEMON_SUBMIT_VERDICT.md sec. 2.1), tagged
        by `verdict`; a rejection is a verdict, not a refusal."""
        return self.call('tx_submit', {'body': b64(body)})

    # Mining.

    def block_template(self):
        return self.call('block_template')

    def block_submit(self, body):
        return self.call('block_submit', {'body': b64(body)})

    def pow(self, height, hashing, seed = None):
        params = {'height': height, 'hashing': b64(hashing)}
        if seed is not None:
            params['seed'] = seed
        return self.call('pow', params)

    def mine_start(self, threads = 'auto'):
        return self.call('mine_start', {'threads': threads})

    def mine_stop(self):
        return self.call('mine_stop')

    def mine_status(self):
        return self.call('mine_status')

    # Bans.

    def ban_add(self, host, duration = None):
        params = {'host': host}
        if duration is not None:
            params['duration'] = duration
        return self.call('ban_add', params)

    def ban_remove(self, host):
        return self.call('ban_remove', {'host': host})

    def ban_list(self):
        return self.call('ban_list')

    def ban_show(self, host):
        return self.call('ban_show', {'host': host})

    # The armed levers (RT-O9.2): served only by a daemon started armed.

    def dev_block_generate(self, count = 1):
        return self.call('dev_block_generate', {'count': count})

    def dev_chain_pop(self, count = 1):
        return self.call('dev_chain_pop', {'count': count})
