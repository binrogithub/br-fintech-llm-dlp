#!/usr/bin/env node
/**
 * claude-elo guardrail shim
 *
 * 透明转发到 LiteLLM(:4000)，唯一职责：给推理请求体注入 guardrails 列表，
 * 让 BR DLP 拦截机制只对经过本 shim 的流量（即 claude-elo 会话）生效。
 * （OSS 版 LiteLLM 的 key 级 guardrails 是企业版功能，故用请求级注入。）
 */
"use strict";

const http = require("http");

const LISTEN_PORT = parseInt(process.env.ELO_SHIM_PORT || "4020", 10);
const TARGET_HOST = process.env.ELO_TARGET_HOST || "127.0.0.1";
const TARGET_PORT = parseInt(process.env.ELO_TARGET_PORT || "4000", 10);
const GUARDRAILS = (process.env.ELO_GUARDRAILS ||
  "secrets-filter,br-dlp-input,br-dlp-output,br-pii-presidio")
  .split(",").map((s) => s.trim()).filter(Boolean);

// 只对推理端点注入；count_tokens 等辅助端点原样转发
function isInferencePath(url) {
  const p = url.split("?")[0];
  return (
    /\/v1\/messages$/.test(p) ||
    /\/chat\/completions$/.test(p) ||
    /\/v1\/completions$/.test(p) ||
    /\/v1\/responses$/.test(p)
  );
}

const server = http.createServer((req, res) => {
  if (req.method === "GET" && req.url === "/health") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ status: "ok", guardrails: GUARDRAILS }));
    return;
  }

  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    let body = Buffer.concat(chunks);

    const ct = req.headers["content-type"] || "";
    if (
      req.method === "POST" &&
      ct.includes("application/json") &&
      body.length > 0 &&
      isInferencePath(req.url)
    ) {
      try {
        const j = JSON.parse(body.toString("utf8"));
        if (j && typeof j === "object" && !Array.isArray(j)) {
          const existing = Array.isArray(j.guardrails) ? j.guardrails : [];
          j.guardrails = [...new Set([...existing, ...GUARDRAILS])];
          body = Buffer.from(JSON.stringify(j));
        }
      } catch (_) {
        // 非法 JSON 原样转发，由上游报错
      }
    }

    if (process.env.ELO_SHIM_DEBUG === "1" && req.method === "POST") {
      try {
        require("fs").appendFileSync(
          "/tmp/claude-elo-shim-debug.jsonl",
          JSON.stringify({ url: req.url, body: body.toString("utf8").slice(0, 400000) }) + "\n"
        );
      } catch (_) {}
    }

    const headers = { ...req.headers };
    headers.host = `${TARGET_HOST}:${TARGET_PORT}`;
    headers["content-length"] = Buffer.byteLength(body);
    delete headers["transfer-encoding"];

    const upstream = http.request(
      {
        host: TARGET_HOST,
        port: TARGET_PORT,
        method: req.method,
        path: req.url,
        headers,
      },
      (ur) => {
        res.writeHead(ur.statusCode, ur.headers);
        ur.pipe(res); // SSE 流式响应直接管道透传
      }
    );
    upstream.on("error", (e) => {
      // fail-closed：上游不可达时拒绝请求，绝不绕过检测
      res.writeHead(502, { "content-type": "application/json" });
      res.end(JSON.stringify({
        error: { code: "ELO_SHIM_UPSTREAM_ERROR", message: e.message },
      }));
    });
    upstream.end(body);
  });
});

server.listen(LISTEN_PORT, "127.0.0.1", () => {
  console.log(
    `claude-elo shim listening on 127.0.0.1:${LISTEN_PORT} -> ` +
    `${TARGET_HOST}:${TARGET_PORT}, guardrails=[${GUARDRAILS.join(", ")}]`
  );
});
