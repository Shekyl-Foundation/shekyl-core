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

import requests
import json

class Response(dict):
    def __init__(self, d):
        for k in d.keys():
            if type(d[k]) == dict:
                self[k] = Response(d[k])
            elif type(d[k]) == list:
                self[k] = []
                for i in range(len(d[k])):
                    if type(d[k][i]) == dict:
                        self[k].append(Response(d[k][i]))
                    else:
                        self[k].append(d[k][i])
            else:
                self[k] = d[k]

    def __getattr__(self, key):
        return self[key]
    def __setattr__(self, key, value):
        self[key] = value
    def __eq__(self, other):
        if type(other) == dict:
            return self == Response(other)
        if self.keys() != other.keys():
            return False
        for k in self.keys():
            if self[k] != other[k]:
                return False
        return True

def wrap(value):
    """A reply as Response objects wherever it holds a JSON object."""
    if type(value) == dict:
        return Response(value)
    if type(value) == list:
        return [wrap(v) for v in value]
    return value

# The daemon's error classes by their wire code (RPC_WIRE.md; the
# shekyl-rpc-types ErrorClass registry).
ERROR_CLASSES = {
    -32602: 'BadParams',
    -32001: 'RefusedByMethod',
    -32002: 'OutsideTheGrant',
    -32003: 'OverResourceBound',
    -32004: 'NotReady',
    -32005: 'StoreFault',
    -32603: 'Internal',
}

class RpcRefusal(Exception):
    """A daemon's refusal: its class, and the diagnostic's dotted code,
    parameters and message. A caller branches on the class and the code,
    never on the message."""
    def __init__(self, error):
        self.error = error
        self.wire_code = error.get('code')
        self.error_class = ERROR_CLASSES.get(self.wire_code)
        diagnostic = error.get('data') or {}
        self.code = diagnostic.get('code')
        self.parameter = diagnostic.get('parameter') or {}
        self.message = diagnostic.get('message', error.get('message'))
        super().__init__('%s %s: %s' % (self.error_class or self.wire_code, self.code, self.message))

class JSONRPC(object):
    def __init__(self, url):
        self.url = url

    def send_request(self, path, inputs, result_field = None):
        res = requests.post(
            self.url + path,
            data=json.dumps(inputs),
            headers={'content-type': 'application/json'})
        res = res.json()
        
        assert 'error' not in res, res

        if result_field:
            res = res[result_field]

        return Response(res)

    def send_json_rpc_request(self, inputs):
        return self.send_request("/json_rpc", inputs, 'result')

    def call(self, method, params = None):
        """One JSON-RPC 2.0 call to the daemon's `/json_rpc` (the only
        route it serves). `params` is the method's named object, or left
        out. A refusal raises `RpcRefusal`."""
        envelope = {'jsonrpc': '2.0', 'id': 0, 'method': method}
        if params is not None:
            envelope['params'] = params
        res = requests.post(
            self.url + "/json_rpc",
            data=json.dumps(envelope),
            headers={'content-type': 'application/json'}).json()
        if 'error' in res:
            raise RpcRefusal(res['error'])
        return wrap(res['result'])



