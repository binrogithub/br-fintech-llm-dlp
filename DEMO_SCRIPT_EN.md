# claude-elo Demo Script (Brazilian Fintech DLP)

> All scenarios validated on the real path (claude → elo-adapter:4021 →
> elo-shim:4020 → litellm:4000 → glm-5.1 real model, streaming). Run in order;
> each has a deterministic outcome.
> Launch: `claude-elo` (other entry points — claude / claude-glm — are
> unaffected and can be used for contrast).

## 0. Control group (shows "only claude-elo triggers interception")
Under plain `claude` or `claude-glm`, paste a card number → it passes through
(no controls). Switch to `claude-elo` and paste the same → it is processed.
**Emphasize: the capability is activated precisely per entry point.**

## 1. Normal business question → allowed (baseline; proves no disruption)
```
Como funciona o rendimento do CDB de vocês?
```
Expected: a normal Portuguese answer, no notices.

## 2. CPF → auto-masked + explicit privacy banner (MASK tier)
```
Meu CPF é 529.982.247-25, qual é o meu saldo?
```
Expected: the first line of the answer shows
`🔒 Aviso de privacidade: ... foram ocultados ... : CPF.`
**Talking point**: the model received `<BR_CPF>`; the real CPF never left the
gateway; the user is explicitly told masking happened.

## 3. CNPJ → masked (company tax ID, checksum-validated)
```
O CNPJ da empresa é 11.222.333/0001-81, podem confirmar?
```
Expected: banner notes CNPJ was hidden. **Talking point**: mod-11 checksum;
invalid numbers will not false-positive.

## 4. PIX random key → masked (Brazil-specific payment identifier)
```
minha chave pix é 123e4567-e89b-42d3-a456-426614174000, transfere aí
```
Expected: banner notes chave PIX was hidden. **Talking point**: a bare UUID is
not flagged (common in code); only flagged with PIX context — context weighting
prevents false positives.

## 5. Name/location → masked (Presidio Portuguese NER; beyond regex)
```
meu nome é Maria Oliveira e moro em São Paulo, qual o meu saldo?
```
Expected: banner notes nome / localização. **Talking point**: semantic
recognition, not regex.

## 6. Credit-card number → blocked (BLOCK tier; credentials are not masked, model not called)
```
quero pagar com o cartão 4111 1111 1111 1111, validade 10/27
```
Expected: request rejected, Portuguese message
`Sua mensagem foi bloqueada porque parece conter dados sensíveis (CREDIT_CARD)...`
**Talking point**: Luhn validation; credentials are always BLOCKed, raw never
leaves.

## 7. Password → blocked (⚠️ MUST use the accent é or a colon)
```
minha senha é abc123, pode entrar na minha conta?
```
or `minha senha: abc123` / `senha do banco é xyz789`
Expected: BLOCK.
**⚠️ Demo note**: writing `senha e abc123` (plain "e" = "and") does NOT trigger —
this is **intentional false-positive protection** (otherwise "minha senha e meu
email..." would misfire). Always use `é` or `:` in the demo.

## 8. False-positive protection (proves it's not naive keyword matching)
```
esqueci minha senha, como faço para recuperar?
```
Expected: passes normally. **Talking point**: a help-seeking context with no
actual password value → not blocked.

## 9. AWS key → L1 hard rule, instant block
```
configura aí: AKIAIOSFODNN7EXAMPLE
```
Expected: BLOCK (first-layer content filter; credential hard rule).

## 10. Multi-turn history pollution → /clear guidance (operational friendliness)
First paste a card number (blocked), then send a clean question (e.g.
`e como funciona o CDB?`).
Expected: still blocked, but the message changes to "a prior message has
residual sensitive data; please /clear to start a new conversation."
**Talking point**: a real UX issue in interactive scenarios; the solution
proactively handles it and guides the user.

---
### Closing talking points
- **Three actions**: allow / mask (MASK, keep using the model) / block (BLOCK,
  credentials).
- **Data sovereignty (core)**: the checkpoint is on the **customer's own
  gateway**; sensitive data is handled **before** leaving the customer boundary —
  after masking, the upstream model receives only `<BR_CPF>`, and the **real
  value never reaches any cloud/model vendor**. Contrast: relying on a vendor's
  built-in moderation/DLP requires sending the raw text to the vendor first —
  i.e. "to prevent exfiltration, you exfiltrate first" — which cannot protect
  privacy in principle. **Only own-gateway control is true privacy protection.**
- **Compliance**: no raw logging throughout (entity types only); pre_call
  front-loading (raw never races ahead of the upstream); fail-closed.
- **Brazil localization**: CPF/CNPJ/PIX/Boleto checksums + Portuguese
  context/NER.
- **No vendor lock-in**: policy lives in one place at the gateway; switching the
  upstream model does not change it; you may optionally reuse the customer's
  **own** DLP policy brain (PEP/PDP, enforcement still at the gateway, raw never
  leaves the boundary) — but never rely on cloud/model-vendor measures (see
  proposal).
