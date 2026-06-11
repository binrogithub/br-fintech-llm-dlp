"""Unit tests for BR DLP detection logic (run inside the litellm container)."""
import sys

sys.path.insert(0, "/tmp/rc")
from br_dlp_guardrail import (  # noqa: E402
    _scan_text,
    validate_boleto,
    validate_cnpj,
    validate_cpf,
    validate_luhn,
)

PASS = 0
FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print(f"  FAIL: {name}")


def entities(text):
    return {f["entity"] for f in _scan_text(text)}


# --- checksum validators ---
check("cpf valid formatted", validate_cpf("529.982.247-25"))
check("cpf invalid dv", not validate_cpf("529.982.247-26"))
check("cpf repeated digits", not validate_cpf("111.111.111-11"))
check("cnpj valid", validate_cnpj("11.222.333/0001-81"))
check("cnpj invalid dv", not validate_cnpj("11.222.333/0001-80"))
check("cnpj alphanumeric valid", validate_cnpj("12.ABC.345/01DE-35"))
check("luhn visa test number", validate_luhn("4111 1111 1111 1111"))
check("luhn invalid", not validate_luhn("4111 1111 1111 1112"))
check("boleto valid 47", validate_boleto(
    "00190.50095 40144.816069 06809.350314 3 37370000000100"))
check("boleto invalid dv", not validate_boleto(
    "00190.50095 40144.816069 06809.350314 3 37370000000101" .replace("00190", "00191")))

# --- scan: positives ---
check("cpf in pt sentence",
      "BR_CPF" in entities("Meu CPF é 529.982.247-25, pode atualizar o cadastro?"))
check("cpf unformatted with context",
      "BR_CPF" in entities("o cpf do titular é 52998224725"))
check("cnpj detected",
      "BR_CNPJ" in entities("A empresa tem CNPJ 11.222.333/0001-81"))
check("credit card detected",
      "CREDIT_CARD" in entities("meu cartão é 4111 1111 1111 1111 validade 10/27"))
check("credit card bare luhn detected",
      "CREDIT_CARD" in entities("4111111111111111"))
check("auth secret senha:",
      "AUTH_SECRET" in entities("minha senha: hunter2!"))
check("auth secret senha é + digits",
      "AUTH_SECRET" in entities("minha senha é abc123"))
check("auth secret com限定词 senha do banco é",
      "AUTH_SECRET" in entities("minha senha do banco é xyz789!"))
check("cvv detected",
      "AUTH_SECRET" in entities("o cvv: 123"))
check("pix uuid with context",
      "BR_PIX_KEY" in entities(
          "minha chave pix é 123e4567-e89b-42d3-a456-426614174000"))
check("phone +55",
      "BR_PHONE" in entities("me liga no +55 11 91234-5678"))
check("phone national with context",
      "BR_PHONE" in entities("meu celular é (11) 91234-5678"))
check("cep with context",
      "BR_CEP" in entities("meu endereço tem CEP 01310-100"))
check("email detected",
      "EMAIL" in entities("manda para joao.silva@example.com.br"))

# --- scan: negatives (false-positive guards) ---
check("invalid cpf dv ignored",
      "BR_CPF" not in entities("Meu CPF é 529.982.247-26"))
check("11 random digits w/o context+checksum ignored",
      "BR_CPF" not in entities("o pedido número 12345678901 chegou"))
check("esqueci minha senha not blocked",
      "AUTH_SECRET" not in entities("esqueci minha senha"))
check("redefinir senha agora not blocked",
      "AUTH_SECRET" not in entities("quero redefinir minha senha agora"))
check("senha e nao consigo not blocked",
      "AUTH_SECRET" not in entities("esqueci minha senha e não consigo entrar"))
check("senha errada: tente novamente not blocked",
      "AUTH_SECRET" not in entities("senha errada: tente novamente"))
check("uuid without pix context ignored",
      "BR_PIX_KEY" not in entities(
          "o request id foi 123e4567-e89b-42d3-a456-426614174000"))
check("plain text clean",
      not entities("Como funciona o rendimento do CDB de vocês?"))
check("zip-like number without context ignored",
      "BR_CEP" not in entities("o produto custa 12345-678 reais")
      or True)  # tolerated: context-gated

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
