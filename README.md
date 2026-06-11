# BR Fintech 风控（基于 LiteLLM Guardrails）

巴西 fintech 场景的敏感信息防泄漏（DLP）：用户误输入 CPF、卡号、PIX 键、密码等
敏感信息时，在请求离开网关之前**拦截（BLOCK）或脱敏（MASK）**，并以葡语提示用户。

已在本机 LiteLLM Proxy（`/root/LiteLLM`，v1.83.14-stable）上部署并通过端到端验证。

## 架构

```
客户端 ──► LiteLLM Proxy (:4000)
              │
              ├─ L1  secrets-filter        内置 Content Filter（pre_call）
              │      API key / JWT / 私钥 / AWS·GitHub·Slack token → BLOCK
              │
              ├─ L2  br-dlp-input          自定义 Guardrail（pre_call）
              │      正则候选 → 校验位算法(CPF/CNPJ/Luhn/Boleto)
              │              → 葡语上下文加权 → (实体,置信度)
              │              → 策略(br_dlp_policy.yaml) → BLOCK / MASK
              │
              ├─ L2' br-pii-presidio       Presidio 葡语 NER（pre_call）
              │      pt_core_news_md：PERSON/LOCATION → MASK（正则做不到的实体）
              │      analyzer/anonymizer 独立容器，不可用时 fail-closed（500 拒绝）
              │
              ├─ (放行/脱敏后) ──► 上游模型（public-ai / restricted-br 分级别名）
              │
              └─ L2' br-dlp-output         同一引擎（post_call）
                     防止模型/RAG/工具结果回流其他客户的 CPF、账户信息
```

## 触发模式：仅 claude-elo 会话拦截

所有 guardrail 均为 `default_on: false`，**只有请求体携带 `guardrails: [...]`
参数才触发**（OSS 版 LiteLLM 的 key 级 guardrails 是企业版功能，故用请求级注入）。
注入由 `claude-elo` 专属链路完成，其他入口（claude-glm/ccr/budget demo）零影响：

```
claude-elo → elo-adapter(:4021)            elo-shim(:4020)              litellm(:4000)
             anthropic→openai 转换    →    注入 guardrails 参数    →    guardrail 执行
             （复用共享 adapter 代码）      （fail-closed 转发）
```

- `claude-elo` 脚本：`/root/.local/bin/claude-elo`（结构仿 claude-glm）
- 专用 virtual key（alias `claude-elo`）存于 `/root/.config/claude-elo/env`，
  审计日志按 `key_alias: claude-elo` 溯源
- shim/adapter：`shim/server.js` + `start.sh`/`start-adapter.sh`/`stop.sh`，
  PID/日志在 `/tmp/claude-elo-*`；上游不可达时 shim 返回 502（fail-closed）

输入过滤全部 `pre_call` —— 绝不与上游调用并行（`during_call` 会让原文先行外发）。

### 对话历史污染与差异化提示

guardrail 扫的是整个出站请求（含完整对话历史）。一旦某条含 BLOCK 级敏感信息
的消息进了 transcript，由于 Claude Code 每轮都重发全部历史，后续每一轮都会被
持续拦截，直到清除历史——这是正确行为（防止残留敏感数据外泄），但对用户像"卡死"。

为此 guardrail 区分敏感信息来自**当前输入**还是**历史消息**，给两种葡语提示：

| 命中位置 | 提示语 | 引导 |
|---|---|---|
| 当前这条输入 | `block_message_pt` | 移除敏感信息后重试 |
| 仅历史消息（当前输入干净） | `block_message_history_pt` | 新开对话 `/clear` 或删除那条消息 |

审计日志同时记 `blocked_by_history_only: true/false`，运营可据此识别"卡在历史里"
需要引导 `/clear` 的会话。判定逻辑：取最新 `role=user` 消息的下标，若所有 BLOCK
命中都不在该消息中，则判定为历史污染。

### 脱敏显性化（隐私横幅）

MASK 是静默放行的——用户不知道发生过脱敏。开启 `show_mask_notice` 后，
guardrail 会在模型回答前加一条葡语隐私横幅，列出被自动隐藏的数据类型：

```
🔒 Aviso de privacidade: para sua proteção, os seguintes dados sensíveis foram
ocultados automaticamente da sua mensagem antes do envio ao modelo: CPF, nome.
```

实现要点（`br-dlp-output`，post_call）：

- **来源判定**：扫描已脱敏的请求 messages 里的 `<BR_CPF>`/`<PERSON>` 等占位符，
  据此列出被隐藏的实体类型（葡语友好名见 `entity_labels_pt`）。
- **注册顺序**：`br-dlp-output` 必须最后注册。Presidio 会自动把 event_hook
  扩展到 post_call 对响应做脱敏，若排在横幅注入之后会把横幅当普通文本二次
  脱敏（"Aviso"→`<LOCATION>`、"CPF"→`<PERSON>`）。配置注释已说明。
- **流式覆盖**：横幅同时实现了 `async_post_call_success_hook`（非流式）和
  `async_post_call_streaming_iterator_hook`（流式，把横幅作为首个 chunk 注入）。
  Claude Code 等客户端默认流式，缺了流式实现横幅就到不了用户端。
- 仅在确有脱敏且非 BLOCK 时出现；失败静默跳过，不影响正常响应。

## 实体与动作矩阵（`config/br_dlp_policy.yaml`）

| 实体 | 识别方式 | 动作 | 阈值 |
|---|---|---|---|
| BR_CPF | 正则 + **校验位验证** + 上下文 | MASK | 0.85 |
| BR_CNPJ | 正则 + 校验位（含 2026 字母数字新格式） | MASK | 0.80 |
| BR_PIX_KEY | UUID v4 + 必须有 pix/chave 上下文 | MASK | 0.65 |
| BR_PHONE | +55 直判；国内格式需上下文 | MASK | 0.65 |
| BR_CEP | 正则 + 必须有 endereço/cep 上下文 | MASK | 0.65 |
| EMAIL | 正则 | MASK | 0.80 |
| BR_BOLETO | 47 位 linha digitável + **3 段 mod10 校验** | BLOCK | 0.90 |
| CREDIT_CARD | 正则 + **Luhn 校验** | BLOCK | 0.80 |
| AUTH_SECRET | senha/PIN/OTP/CVV 关键词 + 值形态评分 | BLOCK | 0.70 |
| PERSON | Presidio 葡语 NER（pt_core_news_md） | MASK | 0.80 |
| LOCATION | Presidio 葡语 NER | MASK | 0.80 |

误报防护实测：校验位错误的 CPF 不命中；“esqueci minha senha”（求助语，无密码值）
不拦截；无 pix 上下文的裸 UUID（如 request id）不命中。

改策略只需编辑 `config/br_dlp_policy.yaml` 后 `docker compose restart litellm`。

## 文件布局

```
/root/risk-control/
├── guardrails/br_dlp_guardrail.py     # 核心：CustomGuardrail（检测+策略+审计）
├── config/br_dlp_policy.yaml          # 实体→动作/阈值策略（运营可改）
├── shim/                              # claude-elo 触发链路
│   ├── server.js                      #   guardrails 注入 shim（:4020）
│   ├── start.sh / stop.sh             #   shim 启停
│   └── start-adapter.sh               #   elo 专属 anthropic adapter（:4021）
├── presidio/                          # L2' Presidio 葡语层（已启用）
│   ├── docker-compose.presidio.yml    #   analyzer/anonymizer 服务叠加
│   ├── Dockerfile.analyzer-pt         #   构建 presidio-analyzer-pt 镜像（含 pt_core_news_md）
│   ├── analyzer_conf_pt.yaml          #   supported_languages: [pt, en]
│   ├── nlp_conf_pt.yaml               #   spacy 模型与 NER→Presidio 实体映射
│   └── recognizers_pt.yaml            #   精简注册表（NER 自动注册；正则实体归 br_dlp）
└── tests/
    ├── test_detectors.py              # 30 个检测逻辑单测（容器内跑）
    └── test_e2e.py                    # 12 个端到端用例（打 :4000）

/root/LiteLLM/ 中的改动（均有 .bak.br-dlp-* 备份）：
├── docker-compose.yml                 # 挂载 guardrail/.py 与策略文件
└── assets/config/litellm_config.yaml  # guardrails 段 + public-ai/restricted-br 别名
```

## 启动 / 重启

Presidio 层通过 compose 叠加文件运行，三个服务同属 litellm 项目网络：

```bash
cd /root/LiteLLM
docker compose -f docker-compose.yml -f /root/risk-control/presidio/docker-compose.presidio.yml up -d
```

`PRESIDIO_*_API_BASE` 已写入 `/root/LiteLLM/.env`，因此单独
`docker compose up -d litellm`（不带叠加文件）重启 litellm 也不影响 presidio
连接（compose 会提示 orphan 容器，属预期，勿加 `--remove-orphans`）。

## 运行验证

```bash
# 检测逻辑单测（容器内，30 cases）
docker exec litellm_proxy sh -c "mkdir -p /tmp/rc" \
  && docker cp guardrails/br_dlp_guardrail.py litellm_proxy:/tmp/rc/ \
  && docker cp tests/test_detectors.py litellm_proxy:/tmp/rc/ \
  && docker exec litellm_proxy /app/.venv/bin/python3 /tmp/rc/test_detectors.py

# 端到端（16 cases：放行/MASK/BLOCK/葡语提示/误报防护/Presidio NER）
python3 tests/test_e2e.py

# 直接观察某个 guardrail 的脱敏效果（不打真实模型）
curl -s http://localhost:4000/guardrails/apply_guardrail \
  -H "Authorization: Bearer $LITELLM_MASTER_KEY" -H "Content-Type: application/json" \
  -d '{"guardrail_name":"br-pii-presidio","text":"meu nome é João da Silva","language":"pt"}'
# → {"response_text": "meu nome é <PERSON>"}

# 看审计日志（只有实体类型与动作，永不含原文）
docker logs litellm_proxy 2>&1 | grep br_dlp_audit
```

拦截时客户端收到 400，结构化错误体内含 `code: BR_DLP_BLOCKED`、`policy_id`、
实体列表与葡语用户提示，前端可直接透出。

## 关键设计决策

1. **校验位优先于正则**：CPF/CNPJ/卡号/boleto 全部过校验算法，单靠正则误报率
   不可接受（任意 11 位数字 1% 概率碰上 CPF 校验位，叠加上下文要求后远低于此）。
2. **fail-closed**：扫描器自身异常时返回 503 拒绝请求（policy 中 `fail_closed: true`），
   金融场景不允许“检测挂了就裸奔”。
3. **审计日志合规**：`br_dlp_audit` 事件只记录实体类型/分数/动作/request_id，
   `raw_content_logged: false`，已验证日志中检索不到任何测试用原文。
4. **分级路由**：客户端只允许使用业务别名 `public-ai`（无敏感/已脱敏）和
   `restricted-br`（脱敏后个人信息；生产应指向 sa-east-1 私有部署，当前为占位）。
   配合 Virtual Key 的 `models` 限制可强制执行。

## 已知边界与演进路径

- **流式输出未扫描**：post_call hook 只覆盖非流式响应。下一步实现
  `async_post_call_streaming_iterator_hook` 做 chunk 级缓冲扫描。
- **MASK ≠ 令牌化**：`<BR_CPF>` 占位不可恢复原值。需要双向脱敏时，在
  `_apply_policy` 处接 Vault Transform/Transit 生成 `<CUSTOMER:tok_xxx>`。
- **Presidio fail-closed 已实测**：analyzer 容器不可用时请求返回 500
  （`Presidio PII analysis failed`），原文不会外发；恢复容器即自愈。
  延迟开销实测约 10ms 级（pt_core_news_md 短文本，本机容器网络），
  litellm 对相同文本的分析结果有缓存。
- **Presidio NER 模型可升级**：pt_core_news_md 为速度优先；召回不足时在
  `Dockerfile.analyzer-pt` 换 `pt_core_news_lg` 重新构建。
- **OPA 策略外置**：当需要按 user_role/purpose/region 动态决策时，把
  `_apply_policy` 的本地策略表替换为对 OPA 的调用（输入实体列表+请求上下文，
  输出 action/route/policy_id），guardrail 退化为纯执行器。
- **触发已改为 opt-in**（2026-06-11）：`default_on: false`，仅 claude-elo 链路
  注入触发；要恢复"全局强制"只需把 4 个 guardrail 改回 `default_on: true`。
  生产环境若有企业版 license，应改用 key 级 guardrails（按 virtual key 绑定，
  应用侧无法绕过）替代请求级注入。
- **aws_secret_key 用上下文正则而非 prebuilt**：裸 40 位 base64 模式会误杀
  git SHA、网页内容等。本机已踩坑：custom_callbacks.py 的 Exa 搜索 hook 会在
  guardrail 之前往 messages 注入网页搜索结果，其中的 base64 串触发过拦截——
  guardrail 扫的是最终出站载荷，凡是 pre-call 注入内容（RAG/搜索/skills）都会
  被一并检查，规则必须能容忍这类文本。
- **AUTH_SECRET 形态覆盖**："senha: x"、"senha é x"、"senha do banco é x"
  （关键词后 0–3 个限定词）均覆盖；分隔符必须存在（误报防护），
  "senha errada: tente novamente" 类 UI 文案在常见词表里豁免。
