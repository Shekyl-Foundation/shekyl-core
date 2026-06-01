# R2-F2 walkthrough script — payment-request receive & reconcile

**Status.** Draft for product sign-off (2026-06-01).  
**Binds.** `docs/design/SUBADDRESS_UNDER_PQC.md` §5.7.9 (R2-F2), §5.7.11 (5-T tags).  
**Does not implement.** Wallet code — this document is the **closure gate** for End-state 5
minimal design. Implementation tracks **FA-8** (payment requests + reconcile UI).

**Substrate at walkthrough time.**

| Layer | V3.0 at genesis | This walkthrough |
|-------|-----------------|------------------|
| Wire `enc_label` + `label_tag` | **Yes** — FA-11; sentinel `0xFF…` every output | Assumed landed or in review (PR #100) |
| Meaningful `REQUEST` tags on wire | **No** — product flag later | Walk **(b)** accepts sentinel-only launch |
| `PaymentRequest` store + GUI | **No** — FA-8 | Use **spec walkthrough** (mockups / paper prototype) |
| `shekyl-proofs` dispute APIs | **Exists** — cite in S5 | Reference only |

**How to run.** 60–90 minutes, one facilitator + product owner (+ optional engineer
for “can we build this?” notes). Each section ends with **Pass / Revise / Block**
— only **Pass** on all **(a)–(d)** and **S1–S6** closes R2-F2 per
`SUBADDRESS_UNDER_PQC.md` §11(e).

---

## 1. Facilitator checklist (before you start)

- [ ] Attendees read §5.7.8 (pit of success — no “generate new address” default).
- [ ] Attendees accept **money never depends on the label** (§5.7.9 UX assertion).
- [ ] Materials ready: primary `shekyl:` address (fixture), sample payment-request URI,
      wire diagram (§5.7.11 layering), confidence-tier table (§5.7.9).
- [ ] For GUI sections: wireframes or whiteboard — **not** production wallet required.
- [ ] Note-taker captures **Pass / Revise / Block** and open questions in §6.

**Out of scope for this session.** T6 adversary wargaming (FA-6), account KDF (P3),
consensus changes, Stage 2 actor code.

---

## 2. Confidence tiers (reference card)

Use this card during every scenario. **Amount** tiers can apply even when **label**
is absent (Tier 4 on label dimension only).

| Tier | Name | Label + books condition | UX one-liner |
|------|------|-------------------------|--------------|
| **1** | Auto-reconciled | Label echo matches **one** open request; amount in tolerance; not expired | Silent — already on invoice |
| **2** | Probable | Single open request fits amount+window; label missing or amount slightly off | “Likely invoice X — confirm” (one tap) |
| **3** | Ambiguous | Multiple open requests fit amount+window | Pick candidate or ask for tx proof |
| **4** | Unattributed | No request matches | “Received — not linked to an invoice” (not an error) |

**Launch posture (5-T).** All cooperative Shekyl→Shekyl sends write **uniform**
`enc_label` ciphertext; minimal wallet writes **sentinel** only → receiver sees
Tier **4** on the label axis until FA-8 + feature flag enable `REQUEST` tags.

---

## 3. Gate walkthroughs **(a)–(d)**

### (a) Web-checkout cooperative path → **S1**, Tier 1

**Maps to.** Merchant invoice flow; 95% cooperative case.  
**Pass if.** Feels **as easy as** Monero subaddress-per-invoice (amount pre-filled, one QR).

**Setup (facilitator narrates).**

1. Merchant opens wallet → **Receive** tab.
2. Hero shows **one reusable address** + copy: *“Reuse freely — on-chain private.”*
3. Merchant taps **Create payment request** (not “new address”).
4. Enters: amount `0.15 SKYL`, label `INV-2026-0042`, expiry optional.
5. Wallet shows QR + string:
   `shekyl:<primary>?amount=150000000000&rid=42&label=INV-2026-0042`

**Customer path (mock GUI).**

6. Customer scans QR in Shekyl wallet (feature-flag build **or** narrate future).
7. Confirm screen: amount + *“Invoice: INV-2026-0042.”*
8. Send → tx includes `enc_label` with `REQUEST` + `rid=42` (**feature on**)
   **or** sentinel only at launch — facilitator states which build is being signed off.

**Receiver path (mock GUI).**

9. Refresh detects output; decrypt label → match `PaymentRequest` id 42.
10. **Tier 1:** request → **Matched**; payment appears under **History → Matched**.
11. Optional notification: “Invoice INV-2026-0042 paid.”

**Facilitator questions (product owner answers aloud).**

- Is “create request” discoverable without training?
- Is bare-address copy still available without shaming the user?
- Does Tier 1 feel automatic, not “we guessed”?

| Result | Notes |
|--------|-------|
| ☐ Pass ☐ Revise ☐ Block | |

---

### (b) Cold QR, no return channel → **S3**, Tier 2 acceptable

**Maps to.** Customer pays from phone with no email/chat back to merchant.  
**Pass if.** Tier **2** one-tap on amount+window is **acceptable** when label cannot be echoed.

**Setup.**

1. Same merchant request as (a), but customer uses **another device** with no way to
   send proof off-band (facilitator: “cold QR at register”).
2. **Launch build:** sender wallet is **sentinel-only** → no `rid` on wire.

**Receiver path.**

3. Payment arrives; label decrypts to **sentinel** → label dimension **Tier 4**.
4. **One** open request matches amount + time window → UI shows **Tier 2** badge:
   *“Likely INV-2026-0042 — confirm.”*
5. Merchant one-tap confirm → `ManualMatch` or promoted to Matched per product rules.

**Residual risk sign-off (required under 5-T).**

Facilitator reads aloud from §5.7.9:

> Under **5-T-substrate**, cooperative Shekyl→Shekyl cold QR reaches Tier 1 only when
> the sender feature writes `REQUEST` tags. **At V3.0 launch (sentinel-only), case (b)
> stays Tier 2/3 + optional tx proof** — explicitly accepted.

Product owner: ☐ **I accept** sentinel-only launch for (b)  
Product owner: ☐ **I require** feature-flag sender before mainnet (blocks launch — escalate)

| Result | Notes |
|--------|-------|
| ☐ Pass ☐ Revise ☐ Block | |

---

### (c) Unattributed donation → **S2**, Tier 4

**Maps to.** Friend sends to bare address; no invoice.  
**Pass if.** Reads as **normal income**, not failure or “broken payment.”

**Setup.**

1. Merchant shares **primary address only** (no request URI).
2. Customer sends any amount via Shekyl or external wallet (sentinel on wire).

**Receiver path.**

3. **History → Incoming → Unattributed** (not red error).
4. Copy shown: *“Received — not linked to an invoice. Match to a request, add a note,
   or leave as general income.”*
5. Balance **spendable immediately**; no blocking modal.

**Facilitator questions.**

- Would support staff panic on this row?
- Is “Create request from this payment” discoverable for retroactive books?

| Result | Notes |
|--------|-------|
| ☐ Pass ☐ Revise ☐ Block | |

---

### (d) Wrong-amount / partial payment → **S4**, Tier 2, no false auto-close

**Maps to.** Two open requests same amount **or** payer sends wrong amount.  
**Pass if.** **No** automatic books close on wrong invoice; one-tap probable path OK.

**Setup A — ambiguous amount, no label.**

1. Merchant has **two** pending requests: both `0.15 SKYL`, different labels.
2. Customer pays `0.15` with bare address (sentinel).
3. **No auto-match** to either request; Tier **3** or Unattributed + candidate list.
4. If UI shows hint, **confirm required** before Matched.

**Setup B — wrong amount, label echoed (feature build).**

5. Request for `0.15`; customer pays `0.10` with cooperative label.
6. **LabelUnknown**; request stays **Pending**; funds spendable.

**Facilitator questions.**

- Can merchant accidentally close wrong invoice in one mis-tap?
- Is partial payment copy calm, not accusatory?

| Result | Notes |
|--------|-------|
| ☐ Pass ☐ Revise ☐ Block | |

---

## 4. Merchant scenarios **S1–S6**

Each scenario is a **standalone acceptance test**. Run in any order after (a)–(d)
or integrate: S1=(a), S2=(c), S3=(b), S4=(d).

### S1 — Cooperative QR pay

| Step | Action | Expected |
|------|--------|----------|
| 1 | Create request + QR | Pending request in list |
| 2 | Customer pays via Shekyl GUI + QR | Tier 1 when feature on; Tier 2 at sentinel launch |
| 3 | Merchant opens History | Matched (or one-tap confirm) |
| **Pass** | | Easier or equal to subaddress-per-invoice |

| Result | Notes |
|--------|-------|
| ☐ Pass ☐ Revise ☐ Block | |

### S2 — Bare address pay

| Step | Action | Expected |
|------|--------|----------|
| 1 | Customer pays primary address only | Unattributed queue |
| 2 | Merchant views row | Not failed; spendable |
| **Pass** | | No panic UX |

| Result | Notes |
|--------|-------|
| ☐ Pass ☐ Revise ☐ Block | |

### S3 — Non-Shekyl sender (no meaningful label)

| Step | Action | Expected |
|------|--------|----------|
| 1 | External wallet sends to primary address | Sentinel or valid uniform ciphertext |
| 2 | Merchant reconcile | Unattributed; amount visible |
| 3 | Optional | Hint if exactly one pending amount match |
| **Pass** | | Reconcile without support ticket |

**Note.** Under **5-T**, wallets that **omit** the fixed-size label slot are
**consensus-invalid**, not “unattributed inter-wallet.” This scenario is
**non-Shekyl but valid FCMP++ PQC tx** (sentinel-shaped label).

| Result | Notes |
|--------|-------|
| ☐ Pass ☐ Revise ☐ Block | |

### S4 — Two open requests, same amount, no label

| Step | Action | Expected |
|------|--------|----------|
| 1 | Two pending requests, same amount | — |
| 2 | One bare payment | No false auto-match |
| 3 | Merchant action | Pick request or leave unattributed |
| **Pass** | | Books not auto-wrong |

| Result | Notes |
|--------|-------|
| ☐ Pass ☐ Revise ☐ Block | |

### S5 — Wrong label echoed

| Step | Action | Expected |
|------|--------|----------|
| 1 | Buggy/malicious sender echoes garbage `REQUEST` rid | Funds received |
| 2 | Attribution | LabelUnknown / Disputed |
| 3 | UI | **Request tx proof** path visible (`shekyl-proofs`) |
| **Pass** | | No fund loss |

| Result | Notes |
|--------|-------|
| ☐ Pass ☐ Revise ☐ Block | |

### S6 — Expired request, late payment

| Step | Action | Expected |
|------|--------|----------|
| 1 | Request expires | State **Expired** |
| 2 | Customer pays stale QR later | Payment **Unattributed** |
| 3 | Merchant | Manual match available; expired row unchanged |
| **Pass** | | Stale QR does not break wallet |

| Result | Notes |
|--------|-------|
| ☐ Pass ☐ Revise ☐ Block | |

---

## 5. UI surface walkthrough (GUI-primary)

Walk each tab once even if scenarios already covered — catches navigation gaps.

### Receive tab

- [ ] Hero: reusable address + privacy copy (§5.7.8).
- [ ] Actions: `Copy address` | `Create payment request` — **no** default “new address.”
- [ ] Bare address available without guilt copy.

### Requests tab

- [ ] Columns: Status, Label, Amount, Created, Actions (QR / Cancel).
- [ ] Pending / Matched / Expired visually distinct.

### History → Incoming

- [ ] Filters or sections: **Matched** | **Needs attention** | **Unattributed**.
- [ ] Row actions: Match to request… | Create request from payment | Request tx proof | Add note.

| Result | Notes |
|--------|-------|
| ☐ Pass ☐ Revise ☐ Block | |

---

## 6. Sign-off record

**R2-F2 closes** when product owner signs **all** rows below. File completed copy
in repo (check boxes, date, initials) or attach meeting notes link.

| Gate | ID | Pass | Owner initials | Date |
|------|-----|------|----------------|------|
| Walkthrough | (a) | ☐ | | |
| Walkthrough | (b) | ☐ | | |
| Walkthrough | (c) | ☐ | | |
| Walkthrough | (d) | ☐ | | |
| Scenario | S1 | ☐ | | |
| Scenario | S2 | ☐ | | |
| Scenario | S3 | ☐ | | |
| Scenario | S4 | ☐ | | |
| Scenario | S5 | ☐ | | |
| Scenario | S6 | ☐ | | |
| UI surfaces | §5 | ☐ | | |
| Residual (b) | 5-T sentinel launch accepted | ☐ | | |

**Sign-off statement (product owner).**

> I confirm that walkthroughs **(a)–(d)** and scenarios **S1–S6** in
> `docs/design/R2_F2_WALKTHROUGH.md` are acceptable for End-state 5 minimal closure
> per `SUBADDRESS_UNDER_PQC.md` §5.7.9, including case **(b)** residual risk under
> sentinel-only V3.0 launch.

Name: _______________________  Date: __________  GitHub / email: _______________________

---

## 7. Issues log (Revise / Block)

| ID | Source | Issue | Disposition | Target |
|----|--------|-------|-------------|--------|
| W-1 | | | | FA-8 / spec amend / V3.1 |

---

## 8. After sign-off

1. Update `SUBADDRESS_UNDER_PQC.md` §11 checklist item **(e)** to `[x]` with date
   (requires that doc on `dev` — lands with PR #100 or follow-up).
2. Land **FA-8** implementation PR(s) against signed spec (no scope drift without
   new design round).
3. Optional: prototype build for regression re-walk before GUI ship.

---

## Related

- Spec: `docs/design/SUBADDRESS_UNDER_PQC.md` §5.7.9–5.7.11 (PR #100)
- Wire: FA-11 / `POST_QUANTUM_CRYPTOGRAPHY.md` label HKDF rows
- Implementation queue: FA-8 in §9 forward-actions table
- Pit of success: §5.7.8, §4.6 (T2 pin)
