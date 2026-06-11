"""
BR DLP Guardrail — LiteLLM Custom Guardrail for Brazilian fintech PII/secret protection.

Detection pipeline per entity:
    regex candidate -> checksum validation (CPF/CNPJ/Luhn/Boleto) ->
    Portuguese context weighting -> (entity, score) -> policy action (BLOCK/MASK)

Design constraints (must hold):
  * pre_call only for input filtering (never during_call: raw data must not
    race ahead to the upstream model).
  * Audit log never contains raw prompt content or matched values.
  * fail-closed: if the scanner itself crashes, the request is rejected
    (configurable via policy `fail_closed`).
"""

import copy
import json
import os
import re
import time
from typing import (
    Any, AsyncGenerator, Dict, List, Literal, Optional, Tuple, Union,
)

from fastapi import HTTPException

from litellm._logging import verbose_proxy_logger
from litellm.caching.caching import DualCache
from litellm.integrations.custom_guardrail import CustomGuardrail
from litellm.proxy._types import UserAPIKeyAuth
from litellm.types.guardrails import GuardrailEventHooks

POLICY_PATH_ENV = "BR_DLP_POLICY_PATH"
DEFAULT_POLICY_PATH = "/app/br_dlp_policy.yaml"

# ---------------------------------------------------------------------------
# checksum validators
# ---------------------------------------------------------------------------


def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)


def validate_cpf(value: str) -> bool:
    d = _digits(value)
    if len(d) != 11 or len(set(d)) == 1:
        return False
    for n in (9, 10):
        s = sum(int(d[i]) * ((n + 1) - i) for i in range(n))
        r = (s * 10) % 11
        if r == 10:
            r = 0
        if r != int(d[n]):
            return False
    return True


def _cnpj_char_value(c: str) -> int:
    # Receita Federal alphanumeric CNPJ (2026+): value = ASCII code - 48
    return ord(c) - 48


def validate_cnpj(value: str) -> bool:
    v = re.sub(r"[^0-9A-Za-z]", "", value).upper()
    if len(v) != 14 or not v[12:].isdigit():
        return False
    if len(set(v)) == 1:
        return False
    weights1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    weights2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    for weights, pos in ((weights1, 12), (weights2, 13)):
        s = sum(_cnpj_char_value(c) * w for c, w in zip(v[:pos], weights))
        dv = 11 - (s % 11)
        if dv >= 10:
            dv = 0
        if dv != int(v[pos]):
            return False
    return True


def validate_luhn(value: str) -> bool:
    d = _digits(value)
    if not 13 <= len(d) <= 19 or len(set(d)) == 1:
        return False
    total = 0
    for i, ch in enumerate(reversed(d)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _boleto_mod10(field: str) -> int:
    total = 0
    weight = 2
    for ch in reversed(field):
        p = int(ch) * weight
        total += p if p < 10 else (p - 9)
        weight = 1 if weight == 2 else 2
    return (10 - total % 10) % 10


def validate_boleto(value: str) -> bool:
    """Validate a 47-digit linha digitavel (bank slip) via its 3 mod-10 field DVs."""
    d = _digits(value)
    if len(d) != 47:
        return False
    fields = ((d[0:9], d[9]), (d[10:20], d[20]), (d[21:31], d[31]))
    return all(_boleto_mod10(f) == int(dv) for f, dv in fields)


# ---------------------------------------------------------------------------
# detectors:  (entity, regex, validator, base_score, context_words)
# A candidate only survives if validator passes (when defined); context words
# found within +/-48 chars add +0.15; `require_context` entities score 0
# without at least one context hit.
# ---------------------------------------------------------------------------

CONTEXT_WINDOW = 48
CONTEXT_BOOST = 0.15

_UUID_V4 = r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"

DETECTORS: List[Dict[str, Any]] = [
    {
        "entity": "BR_CPF",
        "pattern": re.compile(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b"),
        "validator": validate_cpf,
        "base_score": 0.90,
        "context": ["cpf", "cadastro de pessoa", "documento", "titular"],
    },
    {
        "entity": "BR_CPF",
        # unformatted: 11 bare digits — checksum + context keep FP rate low
        "pattern": re.compile(r"(?<![\d.\-/])\d{11}(?![\d.\-/])"),
        "validator": validate_cpf,
        "base_score": 0.70,
        "context": ["cpf", "documento", "titular", "cadastro"],
    },
    {
        "entity": "BR_CNPJ",
        "pattern": re.compile(
            r"\b[0-9A-Za-z]{2}\.?[0-9A-Za-z]{3}\.?[0-9A-Za-z]{3}/?[0-9A-Za-z]{4}-?\d{2}\b"
        ),
        "validator": validate_cnpj,
        "base_score": 0.80,
        "context": ["cnpj", "empresa", "razão social", "razao social"],
    },
    {
        "entity": "CREDIT_CARD",
        "pattern": re.compile(r"\b(?:\d[ -]?){13,19}\b"),
        "validator": validate_luhn,
        "base_score": 0.85,
        "context": ["cartão", "cartao", "crédito", "credito", "card", "visa",
                    "mastercard", "elo", "amex", "validade", "vencimento"],
    },
    {
        "entity": "BR_BOLETO",
        "pattern": re.compile(r"\b\d{5}\.?\d{5}[ .]?\d{5}\.?\d{6}[ .]?\d{5}\.?\d{6}[ .]?\d[ .]?\d{14}\b"),
        "validator": validate_boleto,
        "base_score": 0.95,
        "context": ["boleto", "linha digitável", "linha digitavel", "código de barras",
                    "codigo de barras", "pagamento", "fatura"],
    },
    {
        "entity": "BR_PIX_KEY",
        # EVP (random key) — a bare UUID is too common in code, require context
        "pattern": re.compile(_UUID_V4),
        "validator": None,
        "base_score": 0.55,
        "context": ["pix", "chave", "transferência", "transferencia", "recebedor"],
        "require_context": True,
    },
    {
        "entity": "BR_PHONE",
        "pattern": re.compile(r"\+55\s?\(?\d{2}\)?\s?9?\d{4}[- ]?\d{4}\b"),
        "validator": None,
        "base_score": 0.85,
        "context": ["telefone", "celular", "whatsapp", "contato", "ligar", "pix"],
    },
    {
        "entity": "BR_PHONE",
        # national format without +55 — context required
        "pattern": re.compile(r"\(?\b\d{2}\)?\s?9\d{4}[- ]?\d{4}\b"),
        "validator": None,
        "base_score": 0.55,
        "context": ["telefone", "celular", "whatsapp", "contato", "ligar", "pix"],
        "require_context": True,
    },
    {
        "entity": "BR_CEP",
        "pattern": re.compile(r"\b\d{5}-\d{3}\b"),
        "validator": None,
        "base_score": 0.55,
        "context": ["cep", "endereço", "endereco", "rua", "avenida", "entrega"],
        "require_context": True,
    },
    {
        "entity": "EMAIL",
        "pattern": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
        "validator": None,
        "base_score": 0.80,
        "context": ["email", "e-mail", "pix", "chave", "contato"],
    },
]

# AUTH_SECRET is handled separately: keyword (+ up to 3 qualifier words, e.g.
# "senha do banco") + required separator (:/=/é/eh) + candidate value, scored
# by separator/shape so that "esqueci minha senha" does not trip the rule.
_AUTH_SECRET_RE = re.compile(
    r"(?i)\b(senha|password|pwd|pin|otp|cvv|cvc"
    r"|c[oó]digo\s+de\s+(?:verifica[cç][aã]o|seguran[cç]a|acesso)"
    r"|token\s+de\s+acesso)\b"
    r"(?:\s+\w+){0,3}?"
    r"\s*(?:(?P<sep>[:=])|(?:\bé\b|\beh\b))\s*"
    r"(?P<value>\S{3,})"
)
_COMMON_PT_WORDS = {
    "nova", "novo", "antiga", "antigo", "atual", "errada", "errado", "agora",
    "aqui", "dele", "dela", "minha", "meu", "sua", "seu", "para", "como",
    "incorreta", "incorreto", "esquecida", "bloqueada", "expirada", "expirou",
    "redefinir", "alterar", "trocar", "mudar", "recuperar", "resetar",
    # UI/求助语境常见词（"senha errada: tente novamente" 类误报防护）
    "tente", "digite", "insira", "clique", "novamente", "abaixo", "acima",
    "necessária", "necessario", "obrigatória", "obrigatorio",
    "inválida", "invalido", "fácil", "facil", "muito",
}


def _detect_auth_secret(text: str) -> List[Tuple[int, int, str, float]]:
    out = []
    for m in _AUTH_SECRET_RE.finditer(text):
        value = m.group("value")
        if not value:
            continue
        value_clean = value.strip(".,;!?\"'()")
        if not value_clean or value_clean.lower() in _COMMON_PT_WORDS:
            continue
        score = 0.50
        if m.group("sep"):
            score += 0.30
        if any(c.isdigit() for c in value_clean) or any(
            not c.isalnum() for c in value_clean
        ):
            score += 0.25
        # mask only the secret value, not the keyword
        start = m.start("value")
        end = start + len(value_clean)
        out.append((start, end, "AUTH_SECRET", min(score, 0.99)))
    return out


def _scan_text(text: str) -> List[Dict[str, Any]]:
    """Return findings: [{start, end, entity, score}] (unfiltered by policy)."""
    findings: List[Dict[str, Any]] = []
    lower = text.lower()
    for det in DETECTORS:
        for m in det["pattern"].finditer(text):
            if det["validator"] and not det["validator"](m.group(0)):
                continue
            window = lower[max(0, m.start() - CONTEXT_WINDOW): m.end() + CONTEXT_WINDOW]
            has_ctx = any(w in window for w in det["context"])
            if det.get("require_context") and not has_ctx:
                continue
            score = det["base_score"] + (CONTEXT_BOOST if has_ctx else 0.0)
            findings.append(
                {"start": m.start(), "end": m.end(),
                 "entity": det["entity"], "score": min(score, 0.99)}
            )
    for start, end, entity, score in _detect_auth_secret(text):
        findings.append({"start": start, "end": end, "entity": entity, "score": score})

    # de-overlap: keep highest score, longer span wins ties
    findings.sort(key=lambda f: (f["score"], f["end"] - f["start"]), reverse=True)
    kept: List[Dict[str, Any]] = []
    for f in findings:
        if all(f["end"] <= k["start"] or f["start"] >= k["end"] for k in kept):
            kept.append(f)
    kept.sort(key=lambda f: f["start"])
    return kept


# ---------------------------------------------------------------------------
# guardrail
# ---------------------------------------------------------------------------

DEFAULT_POLICY: Dict[str, Any] = {
    "policy_id": "BR-AI-001",
    "fail_closed": True,
    "entities": {
        "BR_CPF":      {"action": "MASK",  "threshold": 0.85},
        "BR_CNPJ":     {"action": "MASK",  "threshold": 0.80},
        "BR_PIX_KEY":  {"action": "MASK",  "threshold": 0.65},
        "BR_PHONE":    {"action": "MASK",  "threshold": 0.65},
        "BR_CEP":      {"action": "MASK",  "threshold": 0.65},
        "EMAIL":       {"action": "MASK",  "threshold": 0.80},
        "BR_BOLETO":   {"action": "BLOCK", "threshold": 0.90},
        "CREDIT_CARD": {"action": "BLOCK", "threshold": 0.80},
        "AUTH_SECRET": {"action": "BLOCK", "threshold": 0.70},
    },
    "block_message_pt": (
        "Sua mensagem foi bloqueada porque parece conter dados sensíveis "
        "({entities}). Por favor, remova essas informações e tente novamente. "
        "Nunca compartilhe senhas, códigos de segurança ou números de cartão."
    ),
    # 敏感信息来自之前的对话（不是当前这条输入）——清当前输入无济于事，
    # 必须新开对话或清除历史，否则后续每一轮都会被持续拦截。
    "block_message_history_pt": (
        "Esta conversa foi bloqueada porque uma mensagem anterior contém dados "
        "sensíveis ({entities}) que permanecem no histórico. Inicie uma nova "
        "conversa (/clear) ou remova aquela mensagem para continuar. Enquanto "
        "esses dados estiverem no histórico, todas as próximas mensagens serão "
        "bloqueadas."
    ),
    "output_block_message_pt": (
        "A resposta foi retida pela política de segurança porque continha "
        "dados sensíveis ({entities})."
    ),
    # 显性化脱敏：MASK 是静默放行的，用户看不到发生过脱敏。开启后会在模型
    # 回答前加一条隐私横幅，告知哪些敏感信息被自动隐藏。
    "show_mask_notice": True,
    "mask_notice_pt": (
        "🔒 Aviso de privacidade: para sua proteção, os seguintes dados "
        "sensíveis foram ocultados automaticamente da sua mensagem antes do "
        "envio ao modelo: {entities}."
    ),
    # 实体类型 → 葡语友好名（横幅展示用）
    "entity_labels_pt": {
        "BR_CPF": "CPF", "BR_CNPJ": "CNPJ", "BR_PIX_KEY": "chave PIX",
        "BR_PHONE": "telefone", "BR_CEP": "CEP", "EMAIL": "e-mail",
        "PERSON": "nome", "LOCATION": "localização",
    },
}


class BrazilDLPGuardrail(CustomGuardrail):
    def __init__(
        self,
        policy_file: Optional[str] = None,
        **kwargs,
    ):
        # litellm passes through every extra litellm_params key; keep only
        # what CustomGuardrail understands and stash the rest.
        self.policy = self._load_policy(
            policy_file or os.environ.get(POLICY_PATH_ENV, DEFAULT_POLICY_PATH)
        )
        supported = {"guardrail_name", "event_hook", "default_on",
                     "mask_request_content", "mask_response_content"}
        super().__init__(**{k: v for k, v in kwargs.items() if k in supported})
        verbose_proxy_logger.info(
            "BrazilDLPGuardrail '%s' initialized (policy_id=%s, fail_closed=%s)",
            self.guardrail_name, self.policy["policy_id"], self.policy["fail_closed"],
        )

    @staticmethod
    def _load_policy(path: str) -> Dict[str, Any]:
        policy = json.loads(json.dumps(DEFAULT_POLICY))  # deep copy
        try:
            import yaml

            with open(path) as f:
                user_policy = yaml.safe_load(f) or {}
            for k, v in user_policy.items():
                if k == "entities":
                    policy["entities"].update(v)
                else:
                    policy[k] = v
        except FileNotFoundError:
            verbose_proxy_logger.warning(
                "BR DLP policy file %s not found, using built-in defaults", path
            )
        return policy

    # -- core -------------------------------------------------------------

    def _apply_policy(self, text: str) -> Tuple[str, List[Dict[str, Any]], bool]:
        """Returns (masked_text, applied_findings, should_block)."""
        entities_cfg = self.policy["entities"]
        applied = []
        block = False
        for f in _scan_text(text):
            cfg = entities_cfg.get(f["entity"])
            if not cfg or f["score"] < cfg.get("threshold", 0.85):
                continue
            f["action"] = cfg["action"]
            applied.append(f)
            if cfg["action"] == "BLOCK":
                block = True
        masked = text
        for f in sorted(applied, key=lambda x: x["start"], reverse=True):
            if f["action"] == "MASK":
                masked = masked[: f["start"]] + f"<{f['entity']}>" + masked[f["end"]:]
        return masked, applied, block

    def _audit(self, hook: str, applied: List[Dict[str, Any]], blocked: bool,
               request_id: Optional[str], key_alias: Optional[str]) -> None:
        # Compliance: entity types and scores only — never raw content.
        record = {
            "event": "br_dlp_audit",
            "guardrail": self.guardrail_name,
            "policy_id": self.policy["policy_id"],
            "hook": hook,
            "request_id": request_id,
            "key_alias": key_alias,
            "blocked": blocked,
            "entities": [
                {"type": f["entity"], "score": round(f["score"], 2),
                 "action": f["action"]}
                for f in applied
            ],
            # True 表示拦截仅由历史消息触发（当前输入是干净的），即会话
            # 因残留敏感信息持续卡死——运营可据此识别需要引导用户 /clear。
            "blocked_by_history_only": (
                blocked
                and bool([f for f in applied if f["action"] == "BLOCK"])
                and all(
                    not f.get("in_latest_user")
                    for f in applied if f["action"] == "BLOCK"
                )
            ),
            "raw_content_logged": False,
            "ts": time.time(),
        }
        print(json.dumps(record, ensure_ascii=False), flush=True)  # noqa: T201

    def _block_exception(self, applied: List[Dict[str, Any]],
                         message_key: str) -> HTTPException:
        entity_types = sorted({f["entity"] for f in applied if f["action"] == "BLOCK"})
        return HTTPException(
            status_code=400,
            detail={
                "error": {
                    "code": "BR_DLP_BLOCKED",
                    "policy_id": self.policy["policy_id"],
                    "entities": entity_types,
                    "message": self.policy[message_key].format(
                        entities=", ".join(entity_types)
                    ),
                }
            },
        )

    def _fail_closed_exception(self, err: Exception) -> HTTPException:
        verbose_proxy_logger.exception("BR DLP scanner error: %s", type(err).__name__)
        return HTTPException(
            status_code=503,
            detail={
                "error": {
                    "code": "BR_DLP_UNAVAILABLE",
                    "policy_id": self.policy["policy_id"],
                    "message": (
                        "A verificação de segurança está temporariamente "
                        "indisponível. Sua solicitação não foi enviada."
                    ),
                }
            },
        )

    @staticmethod
    def _iter_message_texts(messages: List[Dict[str, Any]]):
        """Yield (container, key, text, msg_idx) for every string content."""
        for msg_idx, msg in enumerate(messages):
            content = msg.get("content")
            if isinstance(content, str):
                yield msg, "content", content, msg_idx
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and isinstance(part.get("text"), str):
                        yield part, "text", part["text"], msg_idx

    @staticmethod
    def _last_user_index(messages: List[Dict[str, Any]]) -> int:
        """Index of the latest user-role message (the one just typed)."""
        return max(
            (i for i, m in enumerate(messages) if m.get("role") == "user"),
            default=-1,
        )

    _PLACEHOLDER_RE = re.compile(r"<([A-Z_]+)>")

    def _masked_entities_in_messages(
        self, messages: List[Dict[str, Any]]
    ) -> List[str]:
        """Entity types whose MASK placeholders are present in the (already
        masked) request messages — i.e. what this guardrail stack redacted on
        the way in. Filtered to known types to avoid matching stray <foo>."""
        known = set(self.policy["entities"].keys()) | {"PERSON", "LOCATION"}
        found: List[str] = []
        for _container, _key, text, _idx in self._iter_message_texts(messages):
            for m in self._PLACEHOLDER_RE.finditer(text):
                ent = m.group(1)
                if ent in known and ent not in found:
                    found.append(ent)
        return found

    def _mask_notice(self, entities: List[str]) -> str:
        labels = self.policy.get("entity_labels_pt", {})
        names = sorted({labels.get(e, e) for e in entities})
        return self.policy["mask_notice_pt"].format(entities=", ".join(names))

    # -- hooks --------------------------------------------------------------

    async def async_pre_call_hook(
        self,
        user_api_key_dict: UserAPIKeyAuth,
        cache: DualCache,
        data: dict,
        call_type: Literal[
            "completion", "text_completion", "embeddings", "image_generation",
            "moderation", "audio_transcription", "pass_through_endpoint",
            "rerank", "mcp_call", "anthropic_messages",
        ],
    ) -> Optional[Union[Exception, str, dict]]:
        if self.should_run_guardrail(data=data, event_type=GuardrailEventHooks.pre_call) is not True:
            return data
        try:
            messages = data.get("messages") or []
            last_user_idx = self._last_user_index(messages)
            all_applied: List[Dict[str, Any]] = []
            block = False
            for container, key, text, msg_idx in self._iter_message_texts(messages):
                masked, applied, should_block = self._apply_policy(text)
                for f in applied:
                    # 命中是在当前这条用户输入里，还是在更早的对话历史里？
                    f["in_latest_user"] = msg_idx == last_user_idx
                all_applied.extend(applied)
                block = block or should_block
                if masked != text:
                    container[key] = masked
        except HTTPException:
            raise
        except Exception as err:
            if self.policy["fail_closed"]:
                raise self._fail_closed_exception(err) from err
            verbose_proxy_logger.exception("BR DLP scan failed (fail-open)")
            return data

        if all_applied:
            self._audit(
                hook="pre_call",
                applied=all_applied,
                blocked=block,
                request_id=data.get("litellm_call_id"),
                key_alias=getattr(user_api_key_dict, "key_alias", None),
            )
        if block:
            # 若所有 BLOCK 命中都来自历史消息（当前输入是干净的），提示用户
            # 清除历史/新开对话；否则提示移除当前输入里的敏感信息。
            block_findings = [f for f in all_applied if f["action"] == "BLOCK"]
            from_history_only = bool(block_findings) and all(
                not f.get("in_latest_user") for f in block_findings
            )
            message_key = (
                "block_message_history_pt" if from_history_only else "block_message_pt"
            )
            raise self._block_exception(all_applied, message_key)
        return data

    async def async_post_call_success_hook(
        self,
        data: dict,
        user_api_key_dict: UserAPIKeyAuth,
        response: Any,
    ) -> Any:
        if self.should_run_guardrail(data=data, event_type=GuardrailEventHooks.post_call) is not True:
            return response
        try:
            all_applied: List[Dict[str, Any]] = []
            block = False
            for choice in getattr(response, "choices", None) or []:
                message = getattr(choice, "message", None)
                if message is None or not isinstance(message.content, str):
                    continue
                masked, applied, should_block = self._apply_policy(message.content)
                all_applied.extend(applied)
                if should_block:
                    block = True
                    entity_types = sorted(
                        {f["entity"] for f in applied if f["action"] == "BLOCK"}
                    )
                    message.content = self.policy["output_block_message_pt"].format(
                        entities=", ".join(entity_types)
                    )
                elif masked != message.content:
                    message.content = masked
        except Exception as err:
            if self.policy["fail_closed"]:
                raise self._fail_closed_exception(err) from err
            verbose_proxy_logger.exception("BR DLP output scan failed (fail-open)")
            return response

        if all_applied:
            self._audit(
                hook="post_call",
                applied=all_applied,
                blocked=block,
                request_id=data.get("litellm_call_id"),
                key_alias=getattr(user_api_key_dict, "key_alias", None),
            )

        # 显性化输入侧脱敏：若请求消息里有 MASK 占位符（说明入口脱敏过），
        # 在回答前加一条隐私横幅。仅非 block、开关开启时；横幅是提示性的，
        # 失败不应拖垮整个响应，故单独 try 静默处理。
        if not block and self.policy.get("show_mask_notice", True):
            try:
                masked_entities = self._masked_entities_in_messages(
                    data.get("messages") or []
                )
                if masked_entities:
                    choices = getattr(response, "choices", None) or []
                    if choices:
                        msg = getattr(choices[0], "message", None)
                        if msg is not None and isinstance(msg.content, str):
                            msg.content = (
                                self._mask_notice(masked_entities) + "\n\n" + msg.content
                            )
            except Exception:
                verbose_proxy_logger.exception("BR DLP mask-notice failed (skipped)")
        return response

    def _make_banner_chunk(self, template_chunk: Any, notice: str) -> Optional[Any]:
        """Clone a streaming chunk, replacing its delta content with the notice
        so the banner can be emitted as the first chunk of the stream."""
        try:
            banner = copy.deepcopy(template_chunk)
            choices = getattr(banner, "choices", None) or []
            if not choices:
                return None
            for i, ch in enumerate(choices):
                delta = getattr(ch, "delta", None)
                if delta is not None:
                    delta.content = (notice + "\n\n") if i == 0 else ""
                # don't let the banner chunk carry a stop signal
                if hasattr(ch, "finish_reason"):
                    ch.finish_reason = None
            return banner
        except Exception:
            verbose_proxy_logger.exception("BR DLP streaming banner failed (skipped)")
            return None

    async def async_post_call_streaming_iterator_hook(
        self,
        user_api_key_dict: UserAPIKeyAuth,
        response: Any,
        request_data: dict,
    ) -> AsyncGenerator[Any, None]:
        # Streaming counterpart of the mask-notice banner. Claude Code (and most
        # clients) stream, so without this the banner from the success hook never
        # reaches the user. Emit the banner as the first chunk, then pass through.
        notice: Optional[str] = None
        if self.policy.get("show_mask_notice", True):
            try:
                ents = self._masked_entities_in_messages(
                    request_data.get("messages") or []
                )
                if ents:
                    notice = self._mask_notice(ents)
            except Exception:
                notice = None

        emitted = False
        async for item in response:
            if notice and not emitted:
                emitted = True
                banner = self._make_banner_chunk(item, notice)
                if banner is not None:
                    yield banner
            yield item
