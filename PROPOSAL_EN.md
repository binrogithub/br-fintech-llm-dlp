# Proposal: Sensitive-Data Protection (DLP) for LLM Usage — Brazilian Fintech

> Customer-facing implementation proposal. End-user-visible strings (block /
> masking notices) are kept in their Portuguese original. Companion material:
> `DEMO_SCRIPT_EN.md` (demo script), `README.md` (technical detail).

---

## 1. Background & Problem

Employees and business systems increasingly send prompts to LLMs (coding
assistants, customer service, internal Q&A). This opens a **new data-leak
channel: sensitive data accidentally pasted into an LLM prompt** — a channel
the customer's existing network/endpoint DLP never inspects (it does not look
inside "requests bound for an LLM"). For a financial institution regulated by
**LGPD (Brazil's General Data Protection Law)** and the central bank (BACEN),
a CPF, bank card, PIX key, Boleto, or password, once sent out, is irreversible.

**Goal:** establish a **customer-controlled**, real-time checkpoint at the LLM
ingress/egress that, for sensitive data, performs **detect → mask/block →
explicit notice → compliant audit**, without disrupting normal usage.

---

## 2. Solution Overview (Value Proposition)

Insert a set of Guardrails at the **customer's own LiteLLM gateway** that
processes sensitive data on every LLM request **before the upstream model is
called**. Three actions:

| Action | Applies to | Effect |
|---|---|---|
| **Allow** | Normal business text | Zero friction, invisible |
| **Mask (MASK)** | CPF / CNPJ / PIX / phone / name / address / e-mail | Replaced with a placeholder, then the model is still called; **the user is explicitly notified** that masking occurred |
| **Block (BLOCK)** | Bank card / Boleto / password/CVV / API key / private key | Rejected outright; the raw value reaches **no** model |

Differentiators:
- **Data sovereignty & privacy first (core)**: the checkpoint sits on the
  customer's own gateway, so sensitive data is handled **before** it leaves the
  customer boundary — the raw data **never** reaches any cloud/model vendor.
  This is something vendor built-in measures cannot achieve by design (Section 3).
- **Brazil-localized detection**: CPF / CNPJ / credit card / Boleto each use
  **checksum algorithms** (mod-11 / Luhn / mod-10), plus **Portuguese context
  weighting** and **Presidio Portuguese NER** (names/addresses), sharply
  reducing false positives.
- **Explicit masking**: MASK is not silent — the user sees a Portuguese privacy
  banner before the model's answer, keeping them informed and trusting.
- **Precise activation**: capability is toggled per entry point (in the demo,
  `claude-elo` triggers it while ordinary entry points are unaffected),
  enabling staged, audience-by-audience rollout.
- **Unified control, model-agnostic**: policy is defined once at the gateway;
  switching the upstream model (GLM / DeepSeek / Claude / private deployment)
  does not change the policy — it never drifts with the vendor.

---

## 3. Why the Checkpoint MUST Be at Your Own Gateway, Not the Cloud/Model Vendor's Built-in Measures (Core Argument)

Many cloud/model vendors offer built-in "content moderation / safety filtering /
vendor-side DLP." Convenient as that sounds, for **sensitive-data protection**
it carries a **fundamental contradiction**:

> **To be inspected by the vendor's measures, the raw text must first be sent to
> the vendor.** In other words, to "prevent sensitive data from leaving," you
> have **already sent it out** — the data has entered the vendor's boundary,
> logs, and possibly its training pipeline. This cannot truly protect privacy.

**The only place that genuinely protects privacy is before data leaves the
customer boundary** — i.e. the customer's own LiteLLM gateway. After this
solution masks/blocks at the gateway, the upstream model only ever receives a
placeholder such as `<BR_CPF>`; **the real sensitive value never leaves the
customer's control.**

### Own-gateway control vs. relying on cloud/model-vendor measures

| Dimension | Rely on cloud/model-vendor built-in measures | Own LiteLLM gateway control (this proposal) |
|---|---|---|
| Does raw sensitive data leave the customer boundary? | **Yes** — raw text must be sent to the vendor to be inspected | **No** — it leaves only after gateway masking/blocking |
| Who sees the raw data | Cloud/model vendor (and its logs; possibly training) | **Only the customer's own gateway** |
| Data residency (LGPD) | Vendor-dependent, often uncontrolled / cross-border | Customer-controlled, in-country (sa-east-1) |
| Policy control | Vendor black box; customer cannot change/inspect | **Customer white box; policy-as-code; auditable** |
| Multi-model consistency | Differs per vendor; changes when you switch models | Unified at gateway; unchanged across upstream models |
| Failure mode | Vendor may fail-open (silent pass) | Customer can enforce **fail-closed** |
| Audit evidence | Depends on vendor logs; raw may be retained | **Own structured audit; raw is never retained** |
| Lock-in risk | Tightly coupled to vendor measures | Decoupled from vendors; free to switch upstream |

**Conclusion:** vendor measures are, at best, a "last redundant layer." **The
first — and decisive — layer must sit on the gateway the customer controls.**
This is the fundamental requirement of data sovereignty and user privacy.

---

## 4. Technical Architecture

```
User / Application
   │  (Anthropic / OpenAI-compatible protocol)
   ▼
Customer-owned LiteLLM gateway  ── Guardrail chain (ordered; all pre_call)
   │
   ├─ L1 credential hard rules   API key / JWT / private key / AWS → BLOCK on hit
   ├─ L2 Brazilian entities      regex → checksum → PT context → policy (MASK/BLOCK)
   ├─ L2 Presidio NER            PT names/addresses (PERSON/LOCATION) → MASK
   │
   ▼  masked/allowed request (placeholders only) ──► upstream model
   │     (the vendor only ever sees <BR_CPF>, never the raw value)
   └─ output-side scan           check model reply for leaked third-party PII + add privacy banner
```

Design constraints (compliance hard rules):
1. **pre_call mandatory**: filtering completes **before** the upstream call.
   Never during_call (which runs in parallel with the upstream call — meaning
   the raw text has already left). This is how "own-gateway control" is realized
   at the request level.
2. **No raw logging**: audit records contain only entity type, action, and
   score, `raw_content_logged=false`; the matched raw value is never logged —
   satisfying the LGPD minimization principle.
3. **fail-closed**: if the scanner itself errors, the request is **rejected**
   (default for finance), never passed through unguarded.
4. **Tiered routing**: clients see only business aliases (public-ai /
   restricted-br), never pick a vendor model directly; requests containing
   masked personal data can be routed to an in-country (sa-east-1) private
   deployment.

---

## 5. Detection Coverage

| Entity | Method | Default action |
|---|---|---|
| BR_CPF (individual taxpayer ID) | regex + mod-11 checksum + context | MASK |
| BR_CNPJ (company ID, incl. 2026 alphanumeric format) | regex + checksum | MASK |
| CREDIT_CARD | Luhn + card-brand context | BLOCK |
| BR_BOLETO (47-digit linha digitável) | 3× mod-10 field checks | BLOCK |
| BR_PIX_KEY (CPF/e-mail/phone/random EVP key) | multi-form + context | MASK |
| AUTH_SECRET (senha/PIN/OTP/CVV/CVC) | keyword + separator + value-shape score | BLOCK |
| BR_PHONE / BR_CEP / EMAIL | regex + context | MASK |
| PERSON / LOCATION (name/address) | Presidio Portuguese NER | MASK |
| API key / JWT / private key / AWS / GitHub / Slack | built-in content filter | BLOCK |

> Thresholds, actions (MASK/BLOCK), and Portuguese messages are all runtime-
> configurable in `br_dlp_policy.yaml`; changes take effect on gateway restart,
> no code change. **All rules and dictionaries are owned by the customer, not a
> vendor black box.**

---

## 6. (Optional) Reuse the Customer's Own DLP Policy Brain — Enforcement Still at the Gateway

If the customer already runs an enterprise DLP internally (with classification,
dictionaries, data fingerprints EDM/IDM), its policy brain can be plugged in —
**but it must be strictly distinguished from "relying on cloud/model-vendor
measures"**:

- The customer's own DLP sits **inside the customer trust boundary**, so sending
  raw text to it for adjudication is acceptable;
- Crucially: **mask/block enforcement still happens at the gateway, data is
  handled before going to the upstream model, and raw text never leaves the
  customer boundary to a cloud/model vendor.**

This uses **PDP / PEP separation**: the customer's own DLP = policy brain (PDP),
the gateway Guardrail = enforcement point (PEP). Implemented via the
`EnterpriseDLPGuardrail` adapter, which only needs to map the customer DLP's
inspection API (a single method), supporting three modes with a staged rollout:

| Phase | Mode | Behavior | Risk |
|---|---|---|---|
| 1. Observe | **shadow** | Call DLP synchronously but do NOT enforce; only log "DLP verdict vs. local verdict" deltas | Zero production impact |
| 2. Audit | **sidecar** | Asynchronously mirror a copy to DLP for audit/SIEM; never blocks, no added latency | Zero blocking risk |
| 3. Enforce | **inline** | Call DLP synchronously and enforce mask/block; DLP verdict is authoritative | Adds DLP latency; needs a fail policy |

**On error** is configurable: `block` (DLP down → reject, fail-closed) or
`passthrough` (DLP down → degrade to the gateway's local layer, so availability
is not coupled to DLP uptime).

> Note: this section is an OPTIONAL enhancement reusing the customer's **own**
> asset, and does not contradict Section 3 ("do not rely on cloud/model-vendor
> measures") — the former stays inside the customer boundary, the latter hands
> data to an external vendor; fundamentally different. Even with no external DLP
> connected, this solution is already a complete loop locally at the gateway.

---

## 7. Deployment & Rollout

**Current state (PoC ready):** the LiteLLM gateway is containerized, Guardrails
are injected as mounted files, and the Presidio Portuguese analyzer/anonymizer
runs as sidecar containers. Validated by 33 unit tests + 25 end-to-end tests +
full real-path demo scenarios.

**Customer-side implementation steps:**
1. **Environment**: deploy the LiteLLM gateway + Presidio Portuguese services
   (containers) in-country (sa-east-1). All components run on customer-owned
   infrastructure; data does not leave the boundary.
2. **Onboarding**: point business/coding-assistant LLM traffic to the gateway
   (OpenAI / Anthropic compatible — just change `base_url`).
3. **Policy**: import `br_dlp_policy.yaml`; with the customer compliance team,
   confirm the MASK/BLOCK tier and Portuguese wording per entity.
4. **(Optional) DLP integration**: if reusing the in-house DLP, follow Section 6
   shadow → sidecar → inline.
5. **Audit integration**: feed the Guardrail's structured audit log (entity
   types only) into the customer SIEM.
6. **Routing**: configure public-ai / restricted-br tiered routing per
   sensitivity level to the corresponding model deployment.
7. **Staged rollout**: enable for a small set of entry points first; expand
   after validating the false-positive rate.

---

## 8. Security & Compliance (LGPD Alignment)

- **Data sovereignty**: control sits on the customer's own gateway; raw
  sensitive data never reaches a cloud/model vendor (Section 3).
- **Data minimization**: audit never records raw text/matched values — only
  entity type + action + score.
- **Front-loaded control**: pre_call guarantees raw text does not race ahead of
  the verdict to the upstream.
- **In-country residency**: all components and requests containing personal data
  can be pinned to an sa-east-1 private deployment.
- **Irreversibility safeguard**: credentials are always BLOCKed, zeroing the
  irreversible-exfiltration risk.
- **fail-closed**: control components default to reject on error, never degrade
  to unguarded.
- **Auditable/explainable**: every action is traceable (virtual key alias); the
  policy file is the compliance artifact, owned by the customer.

---

## 9. Demo (claude-elo)

See `DEMO_SCRIPT_EN.md` — 10 scenarios, all validated on the real path: normal
allow / CPF·CNPJ·PIX·name mask + banner / credit-card·password·Boleto·AWS-key
block / false-positive protection / multi-turn /clear guidance. The demo uses
the `claude-elo` entry point to trigger and the ordinary `claude` entry point as
a control, vividly showing "precise per-entry activation," and emphasizes that
after masking the upstream model sees only placeholders and the raw value never
leaves.

---

## 10. Boundaries & Notes

- MASK is currently placeholder substitution; **reversible tokenization** (masked
  values restorable under authorization) is a future option.
- BLOCK currently returns HTTP 400 + a Portuguese message, which renders in an
  interactive CLI as an informative error (functionally correct); a friendlier
  "soft notice replacing the answer" can be customized.
- **Output-side enforcement on streams** requires buffer-then-adjudicate (you
  cannot recall already-emitted chunks); the privacy banner already supports
  streaming, and output-side DLP enforcement, if enabled, uses buffer-then-
  release (already provisioned).
- False-positive rate is tuned against the customer's real corpus; collect data
  during the staged phase to calibrate thresholds and dictionaries.

---

## 11. Roadmap (Optional Enhancements)

1. **Reversible tokenization**: vault-style mapping, restorable within the
   customer boundary under authorization.
2. **OPA policy engine**: externalize action decisions as governable
   policy-as-code (L3).
3. **(Optional) in-house DLP inline enforcement** (Section 6, phase 3).
4. **Production tiered routing**: point restricted-br to an sa-east-1 private
   deployment.
5. **Self-service false-positive feedback loop**: users flag false positives →
   fed back to tune dictionaries/thresholds.

---

### One-line summary
**Put the sensitive-data checkpoint on the LiteLLM gateway the customer controls
— detect, mask, or block before data ever leaves you, and never hand the raw
text to any cloud/model vendor. This is more thorough privacy protection than
relying on vendor built-in measures.**
