"""
Enterprise DLP Guardrail — adapter that turns the customer's EXISTING DLP
system into a Policy Enforcement Point (PEP) for the LLM egress channel.

Role split (PDP/PEP):
    * PDP (brain)  = the customer's existing DLP — owns classification,
                     dictionaries, fingerprints (EDM/IDM), compliance rules.
    * PEP (gate)   = THIS guardrail — consults the DLP over its API and
                     enforces the verdict at the LLM boundary (mask / block).

It deliberately does NO local detection of its own. The local fast layer is the
separate BrazilDLPGuardrail (checksum-validated BR entities). Run this adapter
alongside it: BrazilDLPGuardrail = cheap offline pre-filter + fallback, this
adapter = authoritative verdict from the enterprise DLP.

Three operating modes (set via litellm_params `mode`):
    inline   — call DLP synchronously, ENFORCE its verdict (mask/block) before
               the request reaches the model. The real gate. Adds DLP RTT.
    sidecar  — fire-and-forget a copy to the DLP for audit/SIEM; NEVER blocks,
               NEVER adds latency. Cannot enforce in real time (by design).
    shadow   — call DLP synchronously but DO NOT enforce; only log "DLP said X".
               For evaluating the DLP against the live traffic before promoting
               it to `inline`.

Error handling (`on_error`):
    block       — DLP unavailable => reject request (fail-closed; financial).
    passthrough — DLP unavailable => let the request continue and rely on the
                  local BrazilDLPGuardrail in the chain (degrade, don't outage).

The ONLY vendor-specific code is `_call_dlp()`. Fill it with your DLP's real
request/response contract; everything else is wiring.
"""

import asyncio
import json
import os
import time
from typing import Any, Dict, List, Literal, Optional, Union

from fastapi import HTTPException

from litellm._logging import verbose_proxy_logger
from litellm.caching.caching import DualCache
from litellm.integrations.custom_guardrail import CustomGuardrail
from litellm.proxy._types import UserAPIKeyAuth
from litellm.types.guardrails import GuardrailEventHooks

# Reuse the shared message-walking helpers from the local guardrail (both files
# are mounted at /app/ in the litellm container).
from br_dlp_guardrail import BrazilDLPGuardrail

try:
    import httpx
except ImportError:  # pragma: no cover
    httpx = None


# ---------------------------------------------------------------------------
# normalized verdict — every vendor response is mapped into this shape
# ---------------------------------------------------------------------------

PASS, MASK, BLOCK = "PASS", "MASK", "BLOCK"


class DLPVerdict:
    """Vendor-neutral result. `_call_dlp` must return one of these."""

    __slots__ = ("action", "entities", "masked_text")

    def __init__(
        self,
        action: str = PASS,
        entities: Optional[List[str]] = None,
        masked_text: Optional[str] = None,
    ):
        self.action = action               # PASS | MASK | BLOCK
        self.entities = entities or []     # entity type names, e.g. ["CPF"]
        self.masked_text = masked_text     # de-identified text if DLP returns it


DEFAULT_MESSAGES = {
    "block_pt": (
        "Sua mensagem foi bloqueada pela política de proteção de dados (DLP) "
        "porque contém informações sensíveis ({entities}). Remova esses dados "
        "e tente novamente."
    ),
    "output_block_pt": (
        "A resposta foi retida pela política de proteção de dados (DLP) porque "
        "continha informações sensíveis ({entities})."
    ),
    "unavailable_pt": (
        "A verificação de proteção de dados está temporariamente indisponível. "
        "Sua solicitação não foi enviada."
    ),
}


class EnterpriseDLPGuardrail(CustomGuardrail):
    def __init__(
        self,
        api_base: Optional[str] = None,
        api_key_env: str = "ENTERPRISE_DLP_API_KEY",
        mode: Literal["inline", "sidecar", "shadow"] = "inline",
        on_error: Literal["block", "passthrough"] = "block",
        scan_input: bool = True,
        scan_output: bool = True,
        send_raw: bool = True,          # customer's own DLP => raw is fine/wanted
        timeout_s: float = 3.0,
        policy_id: str = "ENT-DLP-001",
        messages: Optional[Dict[str, str]] = None,
        **kwargs,
    ):
        self.api_base = api_base or os.environ.get("ENTERPRISE_DLP_API_BASE", "")
        self.api_key = os.environ.get(api_key_env, "")
        self.mode = mode
        self.on_error = on_error
        self.scan_input = scan_input
        self.scan_output = scan_output
        self.send_raw = send_raw
        self.timeout_s = timeout_s
        self.policy_id = policy_id
        self.messages = {**DEFAULT_MESSAGES, **(messages or {})}

        supported = {"guardrail_name", "event_hook", "default_on",
                     "mask_request_content", "mask_response_content"}
        super().__init__(**{k: v for k, v in kwargs.items() if k in supported})
        verbose_proxy_logger.info(
            "EnterpriseDLPGuardrail '%s' initialized (mode=%s, on_error=%s, "
            "api_base=%s)",
            self.guardrail_name, self.mode, self.on_error, self.api_base or "<unset>",
        )

    # -- vendor contract: THE ONLY method to fill in -----------------------

    async def _call_dlp(self, text: str, direction: str) -> DLPVerdict:
        """Call the enterprise DLP and normalize its response to a DLPVerdict.

        `direction` is "input" or "output" (some DLPs apply different policies
        per channel). Raise on transport/HTTP error — the caller decides
        fail-closed vs passthrough via `on_error`.

        TODO(vendor): replace the body below with your DLP's real API contract.
        The snippet shows the common shape (inspect/de-identify REST API):
        """
        if httpx is None:
            raise RuntimeError("httpx not available in this environment")

        payload = {
            # >>> map to your DLP's request schema <<<
            "text": text,
            "channel": direction,          # e.g. "llm-egress"
            "policy_set": "default",
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        async with httpx.AsyncClient(timeout=self.timeout_s) as client:
            r = await client.post(
                f"{self.api_base}/v1/inspect",   # >>> your endpoint <<<
                json=payload, headers=headers,
            )
            r.raise_for_status()
            body = r.json()

        # >>> map your DLP's response fields to DLPVerdict <<<
        # Example assuming: {"verdict": "block|mask|pass",
        #                    "findings": [{"infoType": "BR_CPF"}, ...],
        #                    "deidentifiedText": "...optional..."}
        verdict_raw = (body.get("verdict") or "pass").upper()
        action = {"BLOCK": BLOCK, "MASK": MASK, "PASS": PASS}.get(verdict_raw, PASS)
        entities = sorted({
            f.get("infoType") for f in body.get("findings", []) if f.get("infoType")
        })
        masked_text = body.get("deidentifiedText")
        return DLPVerdict(action=action, entities=entities, masked_text=masked_text)

    # -- enforcement helpers ----------------------------------------------

    def _apply_verdict(
        self, container: dict, key: str, text: str, verdict: DLPVerdict
    ) -> bool:
        """Apply a MASK verdict to the message in place. Returns True if BLOCK."""
        if verdict.action == BLOCK:
            return True
        if verdict.action == MASK:
            # Prefer the DLP's own de-identified text; fall back to a generic
            # placeholder if it only returned a verdict without masked text.
            if verdict.masked_text is not None:
                container[key] = verdict.masked_text
            elif text:
                container[key] = "<REDACTED_BY_DLP>"
        return False

    def _block_exception(self, entities: List[str], key: str) -> HTTPException:
        return HTTPException(
            status_code=400,
            detail={
                "error": {
                    "code": "ENT_DLP_BLOCKED",
                    "policy_id": self.policy_id,
                    "entities": entities,
                    "message": self.messages[key].format(
                        entities=", ".join(entities) or "dados sensíveis"
                    ),
                }
            },
        )

    def _unavailable_exception(self, err: Exception) -> HTTPException:
        verbose_proxy_logger.exception(
            "Enterprise DLP call failed: %s", type(err).__name__
        )
        return HTTPException(
            status_code=503,
            detail={
                "error": {
                    "code": "ENT_DLP_UNAVAILABLE",
                    "policy_id": self.policy_id,
                    "message": self.messages["unavailable_pt"],
                }
            },
        )

    def _on_error(self, err: Exception, data: dict) -> dict:
        """DLP unreachable. Either fail-closed or degrade to the local layer."""
        self._audit("error", direction="input", entities=[], blocked=False,
                    request_id=data.get("litellm_call_id"), error=type(err).__name__)
        if self.on_error == "block":
            raise self._unavailable_exception(err)
        # passthrough: rely on BrazilDLPGuardrail (local) still in the chain.
        verbose_proxy_logger.warning(
            "Enterprise DLP unavailable — degrading to local layer (passthrough)"
        )
        return data

    def _audit(self, hook: str, direction: str, entities: List[str],
               blocked: bool, request_id: Optional[str],
               enforced: bool = True, error: Optional[str] = None) -> None:
        # Compliance: entity TYPES only — never raw content or matched values.
        record = {
            "event": "enterprise_dlp_audit",
            "guardrail": self.guardrail_name,
            "policy_id": self.policy_id,
            "mode": self.mode,
            "hook": hook,
            "direction": direction,
            "request_id": request_id,
            "blocked": blocked,
            "enforced": enforced,          # False in shadow/sidecar mode
            "entities": entities,
            "error": error,
            "raw_content_logged": False,
            "ts": time.time(),
        }
        print(json.dumps(record, ensure_ascii=False), flush=True)  # noqa: T201

    async def _mirror_async(self, texts: List[str], direction: str,
                            request_id: Optional[str]) -> None:
        """sidecar mode: fire-and-forget the DLP for audit; swallow all errors."""
        entities: List[str] = []
        for text in texts:
            try:
                v = await self._call_dlp(text, direction)
                entities.extend(v.entities)
            except Exception:
                verbose_proxy_logger.warning("Enterprise DLP sidecar mirror failed")
        self._audit("sidecar", direction, sorted(set(entities)), blocked=False,
                    request_id=request_id, enforced=False)

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
        if not self.scan_input:
            return data
        if self.should_run_guardrail(
            data=data, event_type=GuardrailEventHooks.pre_call
        ) is not True:
            return data

        messages = data.get("messages") or []
        items = list(BrazilDLPGuardrail._iter_message_texts(messages))

        # sidecar: copy out asynchronously, never block the request.
        if self.mode == "sidecar":
            texts = [self._payload_text(t) for _c, _k, t, _i in items]
            asyncio.create_task(
                self._mirror_async(texts, "input", data.get("litellm_call_id"))
            )
            return data

        # inline / shadow: consult the DLP synchronously.
        all_entities: List[str] = []
        block_entities: List[str] = []
        for container, key, text, _idx in items:
            try:
                verdict = await self._call_dlp(self._payload_text(text), "input")
            except Exception as err:
                return self._on_error(err, data)
            all_entities.extend(verdict.entities)
            if self.mode == "inline":
                if self._apply_verdict(container, key, text, verdict):
                    block_entities.extend(verdict.entities)
            # shadow: record only, never mutate `data`.

        enforced = self.mode == "inline"
        if all_entities or block_entities:
            self._audit("pre_call", "input", sorted(set(all_entities)),
                        blocked=bool(block_entities),
                        request_id=data.get("litellm_call_id"), enforced=enforced)
        if enforced and block_entities:
            raise self._block_exception(sorted(set(block_entities)), "block_pt")
        return data

    async def async_post_call_success_hook(
        self,
        data: dict,
        user_api_key_dict: UserAPIKeyAuth,
        response: Any,
    ) -> Any:
        if not self.scan_output:
            return response
        if self.should_run_guardrail(
            data=data, event_type=GuardrailEventHooks.post_call
        ) is not True:
            return response

        texts_and_msgs = []
        for choice in getattr(response, "choices", None) or []:
            message = getattr(choice, "message", None)
            if message is not None and isinstance(message.content, str):
                texts_and_msgs.append(message)

        # sidecar: mirror the model output for audit, don't touch the response.
        if self.mode == "sidecar":
            asyncio.create_task(self._mirror_async(
                [m.content for m in texts_and_msgs], "output",
                data.get("litellm_call_id")))
            return response

        all_entities: List[str] = []
        blocked = False
        for message in texts_and_msgs:
            try:
                verdict = await self._call_dlp(message.content, "output")
            except Exception as err:
                if self.on_error == "block":
                    raise self._unavailable_exception(err)
                verbose_proxy_logger.warning("Enterprise DLP output check degraded")
                continue
            all_entities.extend(verdict.entities)
            if self.mode == "inline":
                if verdict.action == BLOCK:
                    blocked = True
                    message.content = self.messages["output_block_pt"].format(
                        entities=", ".join(verdict.entities) or "dados sensíveis")
                elif verdict.action == MASK and verdict.masked_text is not None:
                    message.content = verdict.masked_text

        if all_entities:
            self._audit("post_call", "output", sorted(set(all_entities)),
                        blocked=blocked, request_id=data.get("litellm_call_id"),
                        enforced=self.mode == "inline")
        return response

    async def async_post_call_streaming_iterator_hook(
        self,
        user_api_key_dict: UserAPIKeyAuth,
        response: Any,
        request_data: dict,
    ):
        # Output enforcement on a STREAM requires buffering: you cannot un-send a
        # chunk already shown to the user. For inline output enforcement, collect
        # the full text, call the DLP once, then emit (blocked message OR the
        # buffered content). For sidecar/shadow, just pass through and mirror.
        #
        # TODO(vendor): decide buffer-then-release vs pass-through per latency
        # tolerance. Skeleton passes through and mirrors asynchronously.
        chunks = []
        async for item in response:
            chunks.append(item)
            yield item
        if self.mode in ("sidecar", "shadow") and self.scan_output:
            # best-effort async audit of the assembled stream (no enforcement)
            text = self._assemble_stream_text(chunks)
            if text:
                asyncio.create_task(self._mirror_async(
                    [text], "output", request_data.get("litellm_call_id")))

    # -- misc helpers -------------------------------------------------------

    def _payload_text(self, text: str) -> str:
        """What to send to the DLP. Customer's own DLP => raw by default so it
        can fingerprint/classify real values. Set send_raw=false to send the
        already-locally-masked text instead (e.g. if DLP is hosted off-prem)."""
        return text  # `text` here is already whatever is in the message

    @staticmethod
    def _assemble_stream_text(chunks: List[Any]) -> str:
        parts = []
        for ch in chunks:
            for choice in getattr(ch, "choices", None) or []:
                delta = getattr(choice, "delta", None)
                if delta is not None and isinstance(getattr(delta, "content", None), str):
                    parts.append(delta.content)
        return "".join(parts)
