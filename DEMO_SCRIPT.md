# claude-elo Demo 脚本（巴西 Fintech DLP）

> 全部经真实链路验证（claude → elo-adapter:4021 → elo-shim:4020 → litellm:4000 →
> glm-5.1 真实模型，流式）。按顺序演示即可，每条都有确定结果。
> 启动：`claude-elo`（其他入口 claude / claude-glm 不受影响，可对比）。

## 0. 对照组（说明"只有 claude-elo 才拦截"）
普通 `claude` 或 `claude-glm` 下贴卡号 → 正常放行（无风控）。
切到 `claude-elo` 下贴同样内容 → 被处理。**强调：能力是按入口精准启用的。**

## 1. 正常业务问题 → 放行（基线，证明不打扰正常使用）
```
Como funciona o rendimento do CDB de vocês?
```
预期：正常葡语作答，无任何提示。

## 2. CPF → 自动脱敏 + 显性隐私横幅（MASK 档）
```
Meu CPF é 529.982.247-25, qual é o meu saldo?
```
预期：回答第一行出现
`🔒 Aviso de privacidade: ... foram ocultados ... : CPF.`
**讲解点**：模型收到的是 `<BR_CPF>`，真实 CPF 从未离开网关；用户被明确告知发生了脱敏。

## 3. CNPJ → 脱敏（企业税号，带校验位）
```
O CNPJ da empresa é 11.222.333/0001-81, podem confirmar?
```
预期：横幅提示 CNPJ 被隐藏。**讲解点**：带 mod-11 校验位，无效号码不会误报。

## 4. PIX 随机键 → 脱敏（巴西特有支付标识）
```
minha chave pix é 123e4567-e89b-42d3-a456-426614174000, transfere aí
```
预期：横幅提示 chave PIX 被隐藏。**讲解点**：裸 UUID 不拦（代码里常见），有 PIX 上下文才拦——上下文加权防误报。

## 5. 人名/地名 → 脱敏（Presidio 葡语 NER，正则做不到的）
```
meu nome é Maria Oliveira e moro em São Paulo, qual o meu saldo?
```
预期：横幅提示 nome / localização。**讲解点**：语义识别，非正则。

## 6. 信用卡号 → 直接拦截（BLOCK 档，金融凭据不脱敏、不调模型）
```
quero pagar com o cartão 4111 1111 1111 1111, validade 10/27
```
预期：请求被拒，葡语提示
`Sua mensagem foi bloqueada porque parece conter dados sensíveis (CREDIT_CARD)...`
**讲解点**：Luhn 校验；凭据类一律 BLOCK，原文绝不外发。

## 7. 密码 → 拦截（⚠️ 必须带重音 é 或冒号）
```
minha senha é abc123, pode entrar na minha conta?
```
或 `minha senha: abc123` / `senha do banco é xyz789`
预期：BLOCK。
**⚠️ 演示注意**：写成无重音的 `senha e abc123`（e="和"）不会触发——这是**防误报的有意设计**（否则 "minha senha e meu email..." 会误杀）。演示务必用 `é` 或 `:`。

## 8. 误报防护（证明不是无脑关键词匹配）
```
esqueci minha senha, como faço para recuperar?
```
预期：正常放行。**讲解点**：求助语境不含真实密码值 → 不拦。

## 9. AWS 密钥 → L1 硬规则秒拦
```
configura aí: AKIAIOSFODNN7EXAMPLE
```
预期：BLOCK（第一层内容过滤，凭据类硬规则）。

## 10. 多轮历史污染 → 引导 /clear（运维友好性）
先贴卡号被拒，再发一条干净问题（如 `e como funciona o CDB?`）。
预期：仍被拦，但提示变为"历史里有残留敏感信息，请 /clear 新开对话"。
**讲解点**：交互式场景的真实体验问题，方案已主动处理并引导用户。

---
### 演示话术收束
- **三档动作**：放行 / 脱敏（MASK，可继续用模型）/ 拦截（BLOCK，凭据类）。
- **数据主权（核心）**：把控点在**客户自有网关**，敏感数据在离开客户边界**之前**就被
  处理——脱敏后上游模型只收到 `<BR_CPF>`，**真实值从未到达任何云/模型厂商**。
  对照点：依赖厂商内置审核/DLP，必须先把原文发给厂商才能被检查——等于"为了防外发
  先外发了"，原理上保护不了隐私。**只有在自有网关把控，才是真正的隐私保护。**
- **合规**：全程不落原文日志，只记实体类型；pre_call 前置（原文不抢跑上游）；fail-closed。
- **巴西本地化**：CPF/CNPJ/PIX/Boleto 校验位 + 葡语上下文/NER。
- **不锁定厂商**：策略在网关一处，换上游模型策略不变；可选复用客户**自有** DLP 策略
  大脑（PEP/PDP，执行仍在网关，原文不出边界），但不依赖云/模型厂商措施（见 proposal）。
