# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# RT-P7: the ProVerif model of the RPC channel's handshake, hybridXK
# (docs/design/RPC_CHANNEL.md section 4.1). run.py executes it.
#
# The primitives live in docs/formal/proverif/lib/noise.pvl and the break
# constants in lib/broken.pvl. run.py loads those two, in that order, with
# `proverif -lib`. This file declares the protocol: the two roles, the
# enrolment table, the events, and the queries. EncryptAndHash stays in
# lib/encrypt_and_hash.pvl, which only NNhfs loads: this pattern writes
# `aead` and `mixh` itself.
#
# A break is a parameter of the binding that emits the shared secret. With
# X25519 broken, each Diffie-Hellman result is the public constant
# `broken_dh`; with ML-KEM broken, each shared secret is `broken_kem`. The
# keys and ciphertexts still travel. They protect nothing. That gives the
# attacker at least what a real break would, so a property that survives
# here survives a real break. The two other modellings (a discrete-log rule,
# and a rule recovering a KEM secret from its public key) made the search
# grow without bound; lib/broken.pvl records that.
#
# An edit removes one token. The property that token carries must then fail.
# Each edit is a member of `Edit`, so a typo is a name Python rejects rather
# than a string the generator ignores.
#
# ONE QUERY PER PROVERIF RUN. Grouped, the queries of the unbroken model did
# not fit the memory cap once the second client and injective agreement were
# added. `source` therefore takes the queries to include, and run.py asks
# for one.

from __future__ import annotations

import enum
import pathlib
from dataclasses import dataclass

_PROVERIF_LIB = (
    pathlib.Path(__file__).resolve().parents[3] / "docs" / "formal" / "proverif" / "lib"
)
# Load order: primitives, then the break constants. run.py passes these to
# `proverif -lib` in this order.
LIB = _PROVERIF_LIB / "noise.pvl"
BROKEN = _PROVERIF_LIB / "broken.pvl"

# A proof-search hint. ProVerif proves a property by saturating a set of
# clauses, and which hypothesis it resolves on next decides whether
# saturation ends. Left to its default, two variants grow past the memory
# cap once the second client is enrolled: the unbroken model on each of its
# three authentication queries, and the later-key-leak variant on both of
# its queries. The hint tells ProVerif not to resolve on "the attacker
# knows exp(x, y)" during saturation, and to try it a bounded number of
# times when checking the goal.
#
# A hint changes the search, never the clauses: resolution is sound
# whatever is selected. What it can cost is precision (ProVerif's manual,
# section 6.7.2). A verdict of "true" under the hint is a proof, and the
# price shows up as "cannot be proved", which run.py counts as a failure.
# That price is real: with the hint, a variant that expects an attack
# reports "cannot be proved" instead of finding it. Those variants do not
# carry the hint. The flag lives on the variant, beside the queries it
# applies to.
NOUNIF_DH = "nounif x: point, y: scalar; attacker(exp( *x, *y)) [ignoreAFewTimes].\n"


class Break(enum.Enum):
    """Which primitive's shared secrets are the public constant."""

    DH = "dh"
    KEM = "kem"


class Edit(enum.Enum):
    """One token removed from the pattern. The property it carries must fail."""

    NO_SKEM_MESSAGE_1 = "no_skem_m1"
    NO_SE = "no_se"
    NO_SKEM_MESSAGE_4 = "no_skem_m4"


class Query(enum.Enum):
    DAEMON_AUTH = "daemon_auth"
    CLIENT_AUTH_M3 = "client_auth_m3"
    CLIENT_AUTH_RECORD = "client_auth_record"
    REQUEST_SECRET = "request_secret"
    REPLY_SECRET = "reply_secret"
    IDENTITY_HIDDEN = "identity_hidden"
    IDENTITY_HIDDEN_KEM = "identity_hidden_kem"
    IDENTITY_HIDDEN_AFTER_LEAK = "identity_hidden_after_leak"
    IDENTITY_HIDDEN_KEM_AFTER_LEAK = "identity_hidden_kem_after_leak"
    REACH_CLIENT = "reach_client"
    REACH_DAEMON = "reach_daemon"


class Expectation(enum.Enum):
    """What ProVerif must say.

    `REACHABLE` is inverted by ProVerif itself: the query is `event(...)`,
    which ProVerif tries to show unreachable, and "is false" means the
    event happened. run.py maps that RESULT line onto this value.
    """

    HOLDS = "holds"
    ATTACK = "attack"
    REACHABLE = "reachable"


@dataclass(frozen=True)
class Variant:
    """One configuration of the model, and the verdict each of its queries must have.

    `publish_client` hands the attacker the honest client's static public
    keys at the start. The authentication and secrecy rows do; the identity
    rows do not, or the identity queries would be true by construction.

    `leak_daemon_later` publishes the daemon's static secrets in phase 1,
    after the handshake, which is the forward-secrecy question for the
    client's identity.

    `replicate` is unbounded sessions of each role. The reachability row
    leaves it off: one session shows the claims are about a protocol that
    can run, and finding an honest trace through unbounded sessions is the
    most expensive thing ProVerif is asked here.

    `hint` attaches `NOUNIF_DH`. See that constant.
    """

    name: str
    breaks: frozenset[Break]
    edits: frozenset[Edit]
    publish_client: bool
    leak_daemon_later: bool
    replicate: bool
    hint: bool
    expect: tuple[tuple[Query, Expectation], ...]

    def expectation(self, query: Query) -> Expectation:
        """The pinned verdict for `query`.

        A query this variant does not ask is an error: the table is the
        whole of what the row claims, so a generator cannot emit a query
        the row has no verdict for.
        """
        for candidate, want in self.expect:
            if candidate == query:
                return want
        raise KeyError(f"{self.name} does not ask {query.value}")


def let_dh(name: str, expr: str, breaks: frozenset[Break]) -> str:
    """One Diffie-Hellman binding. A broken X25519 contributes `broken_dh`."""
    if Break.DH in breaks:
        return f"let {name} = broken_dh in"
    return f"let {name} = {expr} in"


def let_shared(name: str, expr: str, breaks: frozenset[Break]) -> str:
    """One ML-KEM shared-secret binding. A broken ML-KEM contributes `broken_kem`."""
    if Break.KEM in breaks:
        return f"let {name} = broken_kem in"
    return f"let {name} = {expr} in"


# The three authentication claims are INJECTIVE: each acceptance answers
# to its own send, so a replayed handshake is not an acceptance. The two
# client claims name the honest client's keys, because the daemon's list
# also carries a second client whose keys the attacker holds, and that
# client is accepted without any honest send, as it should be.
_QUERIES: dict[Query, str] = {
    Query.DAEMON_AUTH: (
        "query rs: point, rk: kempk, h: bitstring;\n"
        "  inj-event(ClientAcceptsDaemon(rs, rk, h)) ==> inj-event(DaemonSentM2(rs, rk, h))."
    ),
    Query.CLIENT_AUTH_M3: (
        "query h: bitstring;\n"
        "  inj-event(DaemonAcceptsClassical(exp(g, cs_dh), kpk(cs_kem), h))\n"
        "    ==> inj-event(ClientSentM3(exp(g, cs_dh), kpk(cs_kem), h))."
    ),
    Query.CLIENT_AUTH_RECORD: (
        "query h: bitstring;\n"
        "  inj-event(DaemonAcceptsHybrid(exp(g, cs_dh), kpk(cs_kem), h))\n"
        "    ==> inj-event(ClientSentFirstRecord(exp(g, cs_dh), kpk(cs_kem), h))."
    ),
    Query.REQUEST_SECRET: "query attacker(first_request).",
    Query.REPLY_SECRET: "query attacker(first_reply).",
    Query.IDENTITY_HIDDEN: "query attacker(exp(g, cs_dh)).",
    Query.IDENTITY_HIDDEN_KEM: "query attacker(kpk(cs_kem)).",
    Query.IDENTITY_HIDDEN_AFTER_LEAK: "query attacker(exp(g, cs_dh)) phase 1.",
    Query.IDENTITY_HIDDEN_KEM_AFTER_LEAK: "query attacker(kpk(cs_kem)) phase 1.",
    # Not properties: these must be REACHABLE, or every claim above is true
    # of a protocol that cannot run.
    Query.REACH_CLIENT: (
        "query s: point, sk: kempk, h: bitstring; event(ClientSentFirstRecord(s, sk, h))."
    ),
    # The daemon's, for the honest client specifically: with a second client
    # in the attacker's hands, "some client was accepted" proves nothing.
    Query.REACH_DAEMON: (
        "query h: bitstring; event(DaemonAcceptsHybrid(exp(g, cs_dh), kpk(cs_kem), h))."
    ),
}

_HEADER = """(* ---- generated by rust/shekyl-rpc-channel/model/model.py; do not edit ---- *)
(* Primitives and nonces n0, n1, n2, and empty are
   docs/formal/proverif/lib/noise.pvl. broken_dh and broken_kem are
   docs/formal/proverif/lib/broken.pvl. Both are loaded with proverif -lib,
   the primitives first. *)

free c: channel.

const protocol_name: bitstring.
const prologue: bitstring.
const grant_request: bitstring.
const grant: bitstring.

(* The long-term secrets. Private, so queries can name them. *)
free rs_dh: scalar [private].
free rs_kem: kemsk [private].
free cs_dh: scalar [private].
free cs_kem: kemsk [private].

(* What must stay secret once the handshake is done. *)
free first_request: bitstring [private].
free first_reply: bitstring [private].

(* A second client the daemon has enrolled, whose static secrets the
   attacker holds: a stolen or malicious device. Public names, so the
   attacker has them from the start. What the daemon sends it is public too;
   the honest client's reply is what must stay secret. *)
free ms_dh: scalar.
free ms_kem: kemsk.
free other_reply: bitstring.

(* The daemon's enrolment list: a static key pair and what that client is
   served. One daemon process admits whoever is on it. *)
table enrolled(point, kempk, bitstring).

event DaemonSentM2(point, kempk, bitstring).
event ClientAcceptsDaemon(point, kempk, bitstring).
event ClientSentM3(point, kempk, bitstring).
event DaemonAcceptsClassical(point, kempk, bitstring).
event ClientSentFirstRecord(point, kempk, bitstring).
event DaemonAcceptsHybrid(point, kempk, bitstring).
"""


def _protocol(edits: frozenset[Edit], breaks: frozenset[Break]) -> str:
    """The two roles. `edits` removes tokens; `breaks` selects the public constant."""
    no_skem1 = Edit.NO_SKEM_MESSAGE_1 in edits
    no_se = Edit.NO_SE in edits
    no_skem4 = Edit.NO_SKEM_MESSAGE_4 in edits

    # --- message 1: skem, e, es ---------------------------------------
    if no_skem1:
        client_m1 = """
  let ck1 = hinit(protocol_name) in
  let h1b = hh0 in"""
        daemon_m1 = client_m1
        m1_send, m1_recv = "(epub, ekpub, c1)", "(re: point, rek: kempk, c1: bitstring)"
    else:
        client_m1 = f"""
  new r1: seed;
  let ct1 = kct(rsk, r1) in
  {let_shared("ss1", "kss(rsk, r1)", breaks)}
  let h1 = mixh(hh0, ct2b(ct1)) in
  let ck1 = kdfck(hinit(protocol_name), ss1) in
  let h1b = mixh(h1, kdfh(hinit(protocol_name), ss1)) in"""
        daemon_m1 = f"""
  {let_shared("ss1", "kdecaps(ct1, rs_kem)", breaks)}
  let h1 = mixh(hh0, ct2b(ct1)) in
  let ck1 = kdfck(hinit(protocol_name), ss1) in
  let h1b = mixh(h1, kdfh(hinit(protocol_name), ss1)) in"""
        m1_send = "(ct1, epub, ekpub, c1)"
        m1_recv = "(ct1: kemct, re: point, rek: kempk, c1: bitstring)"

    # --- message 3: s, se ---------------------------------------------
    if no_se:
        client_se = """
  let ck5 = ck4 in
  let c3 = aead(k4, n0x, h8, grant_request) in"""
        daemon_se = """
  let ck5 = ck4 in
  let (=grant_request) = adec(k4, n0x, h8, c3) in"""
        key_after_s = "k4"
        nonce_m4_ct = "n1x"
    else:
        client_se = f"""
  {let_dh("dh_se", "exp(re, cs_dh)", breaks)}
  let ck5 = kdfck(ck4, p2b(dh_se)) in
  let k5 = kdfk(ck4, p2b(dh_se)) in
  let c3 = aead(k5, n0, h8, grant_request) in"""
        daemon_se = f"""
  {let_dh("dh_se", "exp(spub, e_r)", breaks)}
  let ck5 = kdfck(ck4, p2b(dh_se)) in
  let k5 = kdfk(ck4, p2b(dh_se)) in
  let (=grant_request) = adec(k5, n0, h8, c3) in"""
        key_after_s = "k5"
        nonce_m4_ct = "n1"

    # --- message 4: skem -----------------------------------------------
    if no_skem4:
        daemon_m4 = f"""
  let ck6 = ck5 in
  let h11 = h9 in
  let c4 = aead({key_after_s}, {nonce_m4_ct}, h11, grant) in
  let h12 = mixh(h11, c4) in
  out(c, c4);"""
        client_m4 = f"""
  in(c, c4: bitstring);
  let ck6 = ck5 in
  let h11 = h9 in
  let (=grant) = adec({key_after_s}, {nonce_m4_ct}, h11, c4) in
  let h12 = mixh(h11, c4) in"""
    else:
        daemon_m4 = f"""
  new r4: seed;
  let ct4 = kct(skpub, r4) in
  {let_shared("ss4", "kss(skpub, r4)", breaks)}
  let cct4 = aead({key_after_s}, {nonce_m4_ct}, h9, ct2b(ct4)) in
  let h10 = mixh(h9, cct4) in
  let ck6 = kdfck(ck5, ss4) in
  let k6 = kdfk(ck5, ss4) in
  let h11 = mixh(h10, kdfh(ck5, ss4)) in
  let c4 = aead(k6, n0, h11, grant) in
  let h12 = mixh(h11, c4) in
  out(c, (cct4, c4));"""
        client_m4 = f"""
  in(c, (cct4: bitstring, c4: bitstring));
  let ct2b(ct4) = adec({key_after_s}, {nonce_m4_ct}, h9, cct4) in
  {let_shared("ss4", "kdecaps(ct4, cs_kem)", breaks)}
  let h10 = mixh(h9, cct4) in
  let ck6 = kdfck(ck5, ss4) in
  let k6 = kdfk(ck5, ss4) in
  let h11 = mixh(h10, kdfh(ck5, ss4)) in
  let (=grant) = adec(k6, n0, h11, c4) in
  let h12 = mixh(h11, c4) in"""

    # With `se` removed the key of message 3's payload is still k4, which has
    # already sealed three things; those uses take their own nonce names.
    # n0 and n1 belong to the library; these two exist only for this edit.
    extra_nonces = "const n0x: bitstring.\nconst n1x: bitstring.\n" if no_se else ""

    return extra_nonces + f"""
let Client(rs: point, rsk: kempk) =
  let hh0 = mixh(mixh(mixh(hinit(protocol_name), prologue), p2b(rs)), kpk2b(rsk)) in
  (* message 1 *){client_m1}
  new e_i: scalar;
  new ek_i: kemsk;
  let epub = exp(g, e_i) in
  let ekpub = kpk(ek_i) in
  let h2 = mixh(mixh(h1b, p2b(epub)), kpk2b(ekpub)) in
  {let_dh("dh_es", "exp(rs, e_i)", breaks)}
  let ck2 = kdfck(ck1, p2b(dh_es)) in
  let k2 = kdfk(ck1, p2b(dh_es)) in
  let c1 = aead(k2, n0, h2, empty) in
  let h3 = mixh(h2, c1) in
  out(c, {m1_send});
  (* message 2 *)
  in(c, (ct2: kemct, re: point, rek: kempk, c2: bitstring));
  {let_shared("ss2", "kdecaps(ct2, ek_i)", breaks)}
  let h4 = mixh(h3, ct2b(ct2)) in
  let ck3 = kdfck(ck2, ss2) in
  let h5 = mixh(mixh(h4, p2b(re)), kpk2b(rek)) in
  {let_dh("dh_ee", "exp(re, e_i)", breaks)}
  let ck4 = kdfck(ck3, p2b(dh_ee)) in
  let k4 = kdfk(ck3, p2b(dh_ee)) in
  let (=empty) = adec(k4, n0, h5, c2) in
  let h6 = mixh(h5, c2) in
  event ClientAcceptsDaemon(rs, rsk, h6);
  (* message 3 *)
  let spub = exp(g, cs_dh) in
  let skpub = kpk(cs_kem) in
  let cs1 = aead(k4, n1, h6, p2b(spub)) in
  let h7 = mixh(h6, cs1) in
  let cs2 = aead(k4, n2, h7, kpk2b(skpub)) in
  let h8 = mixh(h7, cs2) in{client_se}
  let h9 = mixh(h8, c3) in
  event ClientSentM3(spub, skpub, h9);
  out(c, (cs1, cs2, c3));
  (* message 4 *){client_m4}
  (* first transport record *)
  event ClientSentFirstRecord(spub, skpub, h12);
  out(c, aead(split1(ck6), n0, empty, first_request));
  in(c, reply: bitstring);
  let answer = adec(split2(ck6), n0, empty, reply) in
  0.

let Daemon() =
  let rs = exp(g, rs_dh) in
  let rsk = kpk(rs_kem) in
  let hh0 = mixh(mixh(mixh(hinit(protocol_name), prologue), p2b(rs)), kpk2b(rsk)) in
  (* message 1 *)
  in(c, {m1_recv});{daemon_m1}
  let h2 = mixh(mixh(h1b, p2b(re)), kpk2b(rek)) in
  {let_dh("dh_es", "exp(re, rs_dh)", breaks)}
  let ck2 = kdfck(ck1, p2b(dh_es)) in
  let k2 = kdfk(ck1, p2b(dh_es)) in
  let (=empty) = adec(k2, n0, h2, c1) in
  let h3 = mixh(h2, c1) in
  (* message 2 *)
  new r2: seed;
  new e_r: scalar;
  new ek_r: kemsk;
  let ct2 = kct(rek, r2) in
  {let_shared("ss2", "kss(rek, r2)", breaks)}
  let h4 = mixh(h3, ct2b(ct2)) in
  let ck3 = kdfck(ck2, ss2) in
  let epub_r = exp(g, e_r) in
  let ekpub_r = kpk(ek_r) in
  let h5 = mixh(mixh(h4, p2b(epub_r)), kpk2b(ekpub_r)) in
  {let_dh("dh_ee", "exp(re, e_r)", breaks)}
  let ck4 = kdfck(ck3, p2b(dh_ee)) in
  let k4 = kdfk(ck3, p2b(dh_ee)) in
  let c2 = aead(k4, n0, h5, empty) in
  let h6 = mixh(h5, c2) in
  event DaemonSentM2(rs, rsk, h6);
  out(c, (ct2, epub_r, ekpub_r, c2));
  (* message 3 *)
  in(c, (cs1: bitstring, cs2: bitstring, c3: bitstring));
  let p2b(spub) = adec(k4, n1, h6, cs1) in
  let h7 = mixh(h6, cs1) in
  let kpk2b(skpub) = adec(k4, n2, h7, cs2) in
  let h8 = mixh(h7, cs2) in{daemon_se}
  let h9 = mixh(h8, c3) in
  (* enrolment: only statics on the list are admitted, both halves of one
     entry *)
  get enrolled(=spub, =skpub, reply_for_it) in
  event DaemonAcceptsClassical(spub, skpub, h9);
  (* message 4 *){daemon_m4}
  (* first transport record: nothing is served before it opens *)
  in(c, record: bitstring);
  (* Any record that opens under the session key is accepted: what the
     daemon learns is that the sender holds the key, not what was sent.
     Requiring the secret `first_request` here would make this event
     unreachable for an attacker whatever the handshake did -- which the
     named edit that removes message 4's skem exposed, by passing. *)
  let request = adec(split1(ck6), n0, empty, record) in
  event DaemonAcceptsHybrid(spub, skpub, h12);
  out(c, aead(split2(ck6), n0, empty, reply_for_it)).
"""


def _main_process(publish_client: bool, leak_daemon_later: bool, replicate: bool) -> str:
    publish = "out(c, (exp(g, cs_dh), kpk(cs_kem)));" if publish_client else ""
    leak = "| (phase 1; out(c, (rs_dh, rs_kem)))" if leak_daemon_later else ""
    bang = "!" if replicate else ""
    return f"""
process
  (* Two clients are enrolled: the honest one, and one whose keys the
     attacker holds. *)
  insert enrolled(exp(g, cs_dh), kpk(cs_kem), first_reply);
  insert enrolled(exp(g, ms_dh), kpk(ms_kem), other_reply);
  (* The daemon's bundle is not a secret: every enrolled client holds it. *)
  out(c, (exp(g, rs_dh), kpk(rs_kem)));
  {publish}
  ( ({bang}Client(exp(g, rs_dh), kpk(rs_kem)))
  | ({bang}Daemon())
  {leak} )
"""


def _variant(
    name: str,
    *,
    breaks: tuple[Break, ...] = (),
    edits: tuple[Edit, ...] = (),
    publish_client: bool,
    leak_daemon_later: bool,
    replicate: bool = True,
    hint: bool = False,
    expect: tuple[tuple[Query, Expectation], ...],
) -> Variant:
    asked = [query for query, _want in expect]
    if len(asked) != len(set(asked)):
        raise ValueError(f"{name} asks a query twice")
    return Variant(
        name=name,
        breaks=frozenset(breaks),
        edits=frozenset(edits),
        publish_client=publish_client,
        leak_daemon_later=leak_daemon_later,
        replicate=replicate,
        hint=hint,
        expect=expect,
    )


# Sanity first: one session of each role runs to completion (`reachable`).
# Section 4.1: daemon authentication is hybrid; client authentication is
# classical at message 3 and hybrid at the first record. With both primitives
# broken nothing should hold. Section 4.2: the client's identity is hidden
# from the path, under either break, and stays hidden if the daemon's key
# leaks later. Each named edit removes one token; the property it carries
# must fail.
VARIANTS: tuple[Variant, ...] = (
    _variant(
        "reachable",
        publish_client=True,
        leak_daemon_later=False,
        replicate=False,
        expect=(
            (Query.REACH_CLIENT, Expectation.REACHABLE),
            (Query.REACH_DAEMON, Expectation.REACHABLE),
        ),
    ),
    _variant(
        "baseline",
        publish_client=True,
        leak_daemon_later=False,
        hint=True,
        expect=(
            (Query.DAEMON_AUTH, Expectation.HOLDS),
            (Query.CLIENT_AUTH_M3, Expectation.HOLDS),
            (Query.CLIENT_AUTH_RECORD, Expectation.HOLDS),
            (Query.REQUEST_SECRET, Expectation.HOLDS),
            (Query.REPLY_SECRET, Expectation.HOLDS),
        ),
    ),
    _variant(
        "x25519_broken",
        breaks=(Break.DH,),
        publish_client=True,
        leak_daemon_later=False,
        expect=(
            (Query.DAEMON_AUTH, Expectation.HOLDS),
            (Query.CLIENT_AUTH_M3, Expectation.ATTACK),
            (Query.CLIENT_AUTH_RECORD, Expectation.HOLDS),
            (Query.REQUEST_SECRET, Expectation.HOLDS),
            (Query.REPLY_SECRET, Expectation.HOLDS),
        ),
    ),
    _variant(
        "mlkem_broken",
        breaks=(Break.KEM,),
        publish_client=True,
        leak_daemon_later=False,
        expect=(
            (Query.DAEMON_AUTH, Expectation.HOLDS),
            (Query.CLIENT_AUTH_M3, Expectation.HOLDS),
            (Query.CLIENT_AUTH_RECORD, Expectation.HOLDS),
            (Query.REQUEST_SECRET, Expectation.HOLDS),
            (Query.REPLY_SECRET, Expectation.HOLDS),
        ),
    ),
    _variant(
        "both_broken",
        breaks=(Break.DH, Break.KEM),
        publish_client=True,
        leak_daemon_later=False,
        expect=(
            (Query.DAEMON_AUTH, Expectation.ATTACK),
            (Query.CLIENT_AUTH_RECORD, Expectation.ATTACK),
            (Query.REQUEST_SECRET, Expectation.ATTACK),
        ),
    ),
    _variant(
        "identity",
        publish_client=False,
        leak_daemon_later=False,
        expect=(
            (Query.IDENTITY_HIDDEN, Expectation.HOLDS),
            (Query.IDENTITY_HIDDEN_KEM, Expectation.HOLDS),
        ),
    ),
    _variant(
        "identity_x25519_broken",
        breaks=(Break.DH,),
        publish_client=False,
        leak_daemon_later=False,
        expect=(
            (Query.IDENTITY_HIDDEN, Expectation.HOLDS),
            (Query.IDENTITY_HIDDEN_KEM, Expectation.HOLDS),
        ),
    ),
    _variant(
        "identity_mlkem_broken",
        breaks=(Break.KEM,),
        publish_client=False,
        leak_daemon_later=False,
        expect=(
            (Query.IDENTITY_HIDDEN, Expectation.HOLDS),
            (Query.IDENTITY_HIDDEN_KEM, Expectation.HOLDS),
        ),
    ),
    _variant(
        "identity_daemon_key_leaks_later",
        publish_client=False,
        leak_daemon_later=True,
        hint=True,
        expect=(
            (Query.IDENTITY_HIDDEN_AFTER_LEAK, Expectation.HOLDS),
            (Query.IDENTITY_HIDDEN_KEM_AFTER_LEAK, Expectation.HOLDS),
        ),
    ),
    _variant(
        "edit_no_skem_in_message_1",
        breaks=(Break.DH,),
        edits=(Edit.NO_SKEM_MESSAGE_1,),
        publish_client=True,
        leak_daemon_later=False,
        expect=((Query.DAEMON_AUTH, Expectation.ATTACK),),
    ),
    _variant(
        "edit_no_se_in_message_3",
        edits=(Edit.NO_SE,),
        publish_client=True,
        leak_daemon_later=False,
        expect=((Query.CLIENT_AUTH_M3, Expectation.ATTACK),),
    ),
    _variant(
        "edit_no_skem_in_message_4",
        breaks=(Break.DH,),
        edits=(Edit.NO_SKEM_MESSAGE_4,),
        publish_client=True,
        leak_daemon_later=False,
        expect=((Query.CLIENT_AUTH_RECORD, Expectation.ATTACK),),
    ),
)

_names = [variant.name for variant in VARIANTS]
if len(_names) != len(set(_names)):
    raise ValueError("two variants share a name")


def source(variant: Variant, queries: tuple[Query, ...]) -> str:
    """The ProVerif file for `variant`, containing exactly `queries`.

    Each query must be one the variant pins a verdict for.
    """
    for query in queries:
        variant.expectation(query)
    parts = [_HEADER]
    if variant.hint:
        parts.append(NOUNIF_DH)
    parts.extend(_QUERIES[query] + "\n" for query in queries)
    parts.append(_protocol(variant.edits, variant.breaks))
    parts.append(
        _main_process(variant.publish_client, variant.leak_daemon_later, variant.replicate)
    )
    return "\n".join(parts)
