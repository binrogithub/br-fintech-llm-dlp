#!/usr/bin/env python3
"""端到端验证 BR DLP guardrails（打本机 LiteLLM Proxy :4000）。

用法: python3 tests/test_e2e.py
master key 从 /root/LiteLLM/.env 读取（或环境变量 LITELLM_MASTER_KEY）。
"""
import json
import os
import re
import sys
import urllib.error
import urllib.request

BASE = os.environ.get("LITELLM_BASE", "http://localhost:4000")
MODEL = os.environ.get("DLP_TEST_MODEL", "demo-model")


def master_key():
    if os.environ.get("LITELLM_MASTER_KEY"):
        return os.environ["LITELLM_MASTER_KEY"]
    with open("/root/LiteLLM/.env") as f:
        m = re.search(r'LITELLM_MASTER_KEY\s*=\s*"?([^"\n]+)"?', f.read())
    if not m:
        sys.exit("LITELLM_MASTER_KEY not found")
    return m.group(1)


KEY = master_key()


# 触发模式为 opt-in（default_on: false）：测试请求显式注入 guardrails，
# 模拟 claude-elo shim 的行为；with_guardrails=False 模拟其他普通入口。
GUARDRAILS = ["secrets-filter", "br-dlp-input", "br-dlp-output", "br-pii-presidio"]


def chat(text, with_guardrails=True):
    return chat_messages([{"role": "user", "content": text}], with_guardrails)


def chat_messages(messages, with_guardrails=True):
    """Returns (http_status, parsed_body) for a full message list (multi-turn)."""
    body = {"model": MODEL, "messages": messages}
    if with_guardrails:
        body["guardrails"] = GUARDRAILS
    req = urllib.request.Request(
        f"{BASE}/v1/chat/completions",
        data=json.dumps(body).encode(),
        headers={"Authorization": f"Bearer {KEY}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {}


PASS = FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    mark = "✓" if cond else "✗"
    print(f"  {mark} {name}" + (f"   [{detail}]" if detail and not cond else ""))
    if cond:
        PASS += 1
    else:
        FAIL += 1


def body_text(body):
    return json.dumps(body, ensure_ascii=False)


print(f"target={BASE} model={MODEL}\n")

# 1. 正常葡语业务问题 → 放行
status, body = chat("Como funciona o rendimento do CDB de vocês?")
check("正常葡语文本放行 (200)", status == 200, f"status={status}")

# 2. 无效 CPF（校验位错误）→ 放行（校验位算法防误报）
status, body = chat("Meu CPF é 529.982.247-26, está certo?")
check("无效CPF校验位 → 放行 (200)", status == 200, f"status={status}")

# 3. 有效 CPF → MASK 后放行（200，审计日志可见 MASK 动作）
status, body = chat("Meu CPF é 529.982.247-25, pode atualizar meu cadastro?")
check("有效CPF → MASK后放行 (200)", status == 200, f"status={status}")

# 4. 信用卡号（Luhn 有效）→ BLOCK，葡语提示
status, body = chat("quero pagar com o cartão 4111 1111 1111 1111, validade 10/27")
t = body_text(body)
check("信用卡 → BLOCK (400)", status == 400, f"status={status}")
check("拦截响应含 BR_DLP_BLOCKED + CREDIT_CARD",
      "BR_DLP_BLOCKED" in t and "CREDIT_CARD" in t, t[:300])
check("拦截提示为葡语", "dados sensíveis" in t, t[:300])

# 5. 密码 → BLOCK
status, body = chat("minha senha é abc123, pode entrar na minha conta?")
check("密码 AUTH_SECRET → BLOCK (400)", status == 400,
      f"status={status} {body_text(body)[:200]}")

# 6. “esqueci minha senha” 正常求助 → 放行（误报防护）
status, body = chat("esqueci minha senha, como faço para recuperar?")
check("'esqueci minha senha' → 放行 (200)", status == 200, f"status={status}")

# 7. AWS Access Key → 第一层 content filter BLOCK
status, body = chat("configura aí: AKIAIOSFODNN7EXAMPLE")
check("AWS key → L1 BLOCK (4xx)", 400 <= status < 500,
      f"status={status} {body_text(body)[:200]}")

# 8. JWT → 第一层 BLOCK
status, body = chat(
    "o token é eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
check("JWT → L1 BLOCK (4xx)", 400 <= status < 500, f"status={status}")

# 9. PIX 随机键（UUID+上下文）→ MASK 后放行
status, body = chat(
    "minha chave pix é 123e4567-e89b-42d3-a456-426614174000, transfere aí")
check("PIX key → MASK后放行 (200)", status == 200, f"status={status}")

# 10. Boleto linha digitável → BLOCK
status, body = chat(
    "paga esse boleto: 00190.50095 40144.816069 06809.350314 3 37370000000100")
check("Boleto → BLOCK (400)", status == 400,
      f"status={status} {body_text(body)[:200]}")

# 10b. 差异化验证：不带 guardrails 的普通入口，同样卡号应放行
status, body = chat("cartão 4111 1111 1111 1111", with_guardrails=False)
check("无guardrails入口：卡号放行 (200)", status == 200, f"status={status}")

# 10c. 限定词形态密码 → BLOCK
status, body = chat("minha senha do banco é xyz789!")
check("senha do banco é → BLOCK (400)", status == 400, f"status={status}")

# 10d. 多轮历史污染：第一条含卡号(被拒后残留)，第二条干净输入 →
#      仍 BLOCK，但提示语应是"历史"版本（引导 /clear 新开对话）
history = [
    {"role": "user", "content": "meu cartão é 4111 1111 1111 1111"},
    {"role": "assistant", "content": "Não posso processar dados de cartão."},
    {"role": "user", "content": "ok, e como funciona o CDB de vocês?"},
]
status, body = chat_messages(history)
t = body_text(body)
check("历史污染：仍 BLOCK (400)", status == 400, f"status={status}")
check("历史污染：提示语为历史版（含 /clear 引导）",
      "/clear" in t or "histórico" in t, t[:300])

# 10e. 当前输入含敏感信息 → 提示语为普通版（不含 /clear）
status, body = chat_messages([
    {"role": "user", "content": "antiga conversa limpa"},
    {"role": "assistant", "content": "ok"},
    {"role": "user", "content": "minha senha é abc123"},
])
t = body_text(body)
check("当前输入命中：提示语为普通版（不含 /clear）",
      status == 400 and "/clear" not in t, t[:300])

# 11. 脱敏显性化：CPF 被 MASK 后放行，回答前应出现葡语隐私横幅
status, body = chat("meu CPF é 529.982.247-25, qual o meu saldo?")
content = ""
try:
    content = body["choices"][0]["message"]["content"]
except Exception:
    pass
check("脱敏后放行 (200)", status == 200, f"status={status}")
check("回答含隐私横幅 (Aviso de privacidade)",
      "Aviso de privacidade" in content, content[:200])
check("横幅列出 CPF", "CPF" in content, content[:200])

# 12. 正常文本（无脱敏）→ 不应出现横幅
status, body = chat("Como funciona o rendimento do CDB?")
content = ""
try:
    content = body["choices"][0]["message"]["content"]
except Exception:
    pass
check("无脱敏时不加横幅", "Aviso de privacidade" not in content, content[:150])


# ── Presidio 葡语层（br-pii-presidio，若已启用）──────────────────────────
def apply_guardrail(name, text):
    req = urllib.request.Request(
        f"{BASE}/guardrails/apply_guardrail",
        data=json.dumps({"guardrail_name": name, "text": text,
                         "language": "pt"}).encode(),
        headers={"Authorization": f"Bearer {KEY}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {}


status, body = apply_guardrail(
    "br-pii-presidio",
    "Olá, meu nome é João da Silva e moro em São Paulo.")
if status == 400 and "not found" in body_text(body).lower():
    print("  - Presidio 层未启用，跳过 NER 用例")
else:
    out = body.get("response_text", "")
    check("Presidio: 葡语人名 → <PERSON>", "<PERSON>" in out, out)
    check("Presidio: 城市 → <LOCATION>", "<LOCATION>" in out, out)
    check("Presidio: 原文姓名已移除", "João da Silva" not in out, out)

    # 11. 端到端：含人名的完整请求应 MASK 后放行
    status, body = chat("meu nome é Maria Oliveira, qual o meu saldo?")
    check("含人名请求 → MASK后放行 (200)", status == 200, f"status={status}")

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
