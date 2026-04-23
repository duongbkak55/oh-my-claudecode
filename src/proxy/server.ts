/**
 * AI Egress Proxy HTTP server. Anthropic-compatible /v1/messages, DLP-filtered,
 * allowlist-enforced. Node built-in `http` + `fetch` only — no framework dep.
 */

import { createServer, type IncomingMessage, type ServerResponse, type Server } from "http";
import { randomUUID } from "crypto";
import type { ProxyConfig } from "./config.js";
import { compileConfigPatterns } from "./config.js";
import {
  redactAnthropicRequest,
  redactStreamingChunk,
  type AnthropicRequestBody,
} from "./dlp.js";
import { scanRequestForBannedTools, validateUpstreamUrl } from "./allowlist.js";
import { auditEvent, summarizeMatches } from "./audit.js";
import {
  defaultToolRegistry,
  runAgentLoop,
  type UpstreamClient,
  type UpstreamResponse,
} from "./agent-loop.js";

interface Metrics {
  requests_total: number;
  blocked_total: number;
  redacted_total: number;
  tool_calls_total: number;
  hitl_pending: number;
  errors_total: number;
}

export interface StartedProxy {
  port: number;
  host: string;
  close(): Promise<void>;
  metrics(): Readonly<Metrics>;
}

const MAX_BODY_BYTES_HARD = 5_000_000;

function readBody(req: IncomingMessage, max: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on("data", (c: Buffer) => {
      total += c.length;
      if (total > max) {
        reject(new Error(`Request body exceeds ${max} bytes`));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function writeJson(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(payload).toString(),
  });
  res.end(payload);
}

function clientIp(req: IncomingMessage): string {
  const xf = req.headers["x-forwarded-for"];
  if (typeof xf === "string" && xf.length > 0) return xf.split(",")[0]!.trim();
  return req.socket.remoteAddress ?? "unknown";
}

export interface StartProxyOptions {
  config: ProxyConfig;
  // allow tests to inject a custom upstream (e.g. a local mock server URL)
  upstreamBaseUrlOverride?: string;
}

export async function startProxy(opts: StartProxyOptions): Promise<StartedProxy> {
  const { config } = opts;
  const upstreamBaseUrl = opts.upstreamBaseUrlOverride ?? config.upstream.baseUrl;

  const host = config.listen.host;
  if (
    (host === "0.0.0.0" || host === "::") &&
    process.env.OMC_PROXY_ALLOW_PUBLIC !== "1"
  ) {
    throw new Error(
      `Refusing to bind to public interface '${host}'. Set OMC_PROXY_ALLOW_PUBLIC=1 to override.`,
    );
  }

  const patterns = compileConfigPatterns(config);
  const tools = defaultToolRegistry();
  const metrics: Metrics = {
    requests_total: 0,
    blocked_total: 0,
    redacted_total: 0,
    tool_calls_total: 0,
    hitl_pending: 0,
    errors_total: 0,
  };

  const upstreamClient: UpstreamClient = {
    async createMessage(body) {
      const url = `${upstreamBaseUrl.replace(/\/$/, "")}/v1/messages`;
      const check = validateUpstreamUrl(url, config.allowlist, upstreamBaseUrl);
      if (!check.allowed) {
        throw new Error(`Upstream URL rejected: ${check.reason}`);
      }
      const apiKey = process.env[config.upstream.apiKeyEnv] ?? "";
      const resp = await fetch(url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-api-key": apiKey,
          "anthropic-version": "2023-06-01",
        },
        body: JSON.stringify({ ...body, stream: false }),
      });
      if (!resp.ok) {
        const text = await resp.text();
        throw new Error(`Upstream ${resp.status}: ${text.slice(0, 500)}`);
      }
      return (await resp.json()) as UpstreamResponse;
    },
  };

  const server = createServer(async (req, res) => {
    const reqId = randomUUID();
    const ip = clientIp(req);
    const started = Date.now();
    const url = req.url ?? "/";

    try {
      if (req.method === "GET" && url === "/health") {
        writeJson(res, 200, { status: "ok" });
        return;
      }

      if (req.method === "GET" && url === "/metrics") {
        const lines = [
          `# HELP omc_proxy_requests_total Total requests handled`,
          `# TYPE omc_proxy_requests_total counter`,
          `omc_proxy_requests_total ${metrics.requests_total}`,
          `# HELP omc_proxy_blocked_total Requests or streams blocked by DLP/allowlist`,
          `# TYPE omc_proxy_blocked_total counter`,
          `omc_proxy_blocked_total ${metrics.blocked_total}`,
          `# HELP omc_proxy_redacted_total DLP redaction events`,
          `# TYPE omc_proxy_redacted_total counter`,
          `omc_proxy_redacted_total ${metrics.redacted_total}`,
          `# HELP omc_proxy_tool_calls_total Tool calls processed`,
          `# TYPE omc_proxy_tool_calls_total counter`,
          `omc_proxy_tool_calls_total ${metrics.tool_calls_total}`,
          `# HELP omc_proxy_hitl_pending Current pending HITL approvals`,
          `# TYPE omc_proxy_hitl_pending gauge`,
          `omc_proxy_hitl_pending ${metrics.hitl_pending}`,
          `# HELP omc_proxy_errors_total Internal proxy errors`,
          `# TYPE omc_proxy_errors_total counter`,
          `omc_proxy_errors_total ${metrics.errors_total}`,
          "",
        ];
        res.writeHead(200, { "content-type": "text/plain; version=0.0.4" });
        res.end(lines.join("\n"));
        return;
      }

      if (req.method === "POST" && url === "/v1/messages") {
        metrics.requests_total += 1;

        const apiKey = process.env[config.upstream.apiKeyEnv];
        if (!apiKey) {
          metrics.errors_total += 1;
          writeJson(res, 500, {
            error: {
              type: "config_error",
              message: `Upstream API key env var '${config.upstream.apiKeyEnv}' is not set`,
            },
          });
          auditEvent(config.audit.dir, {
            reqId,
            clientIp: ip,
            phase: "error",
            error: "missing_api_key",
          });
          return;
        }

        const rawBody = await readBody(
          req,
          Math.min(MAX_BODY_BYTES_HARD, config.audit.maxBodyBytes * 5),
        );
        let parsed: AnthropicRequestBody;
        try {
          parsed = JSON.parse(rawBody.toString("utf-8")) as AnthropicRequestBody;
        } catch (err) {
          metrics.errors_total += 1;
          writeJson(res, 400, {
            error: { type: "invalid_json", message: String(err) },
          });
          return;
        }

        const toolScan = scanRequestForBannedTools(parsed, config.allowlist);
        if (!toolScan.allowed) {
          metrics.blocked_total += 1;
          auditEvent(config.audit.dir, {
            reqId,
            clientIp: ip,
            phase: "block",
            model: parsed.model,
            blocked: true,
            bytesIn: rawBody.length,
            latencyMs: Date.now() - started,
            meta: {
              reason: "banned_tool",
              tools: toolScan.blocked.map((b) => b.name).join(","),
            },
          });
          writeJson(res, 400, {
            error: {
              type: "allowlist_blocked",
              message: "Request contains non-allowlisted tools",
              tools: toolScan.blocked,
            },
          });
          return;
        }

        const dlp = redactAnthropicRequest(parsed, patterns);
        if (dlp.blocked) {
          metrics.blocked_total += 1;
          auditEvent(config.audit.dir, {
            reqId,
            clientIp: ip,
            phase: "block",
            model: parsed.model,
            blocked: true,
            bytesIn: rawBody.length,
            dlpMatches: summarizeMatches(dlp.matches),
            latencyMs: Date.now() - started,
          });
          writeJson(res, 400, {
            error: {
              type: "dlp_blocked",
              message: "Request contains sensitive content and was blocked",
              matches: dlp.blockedReasons,
            },
          });
          return;
        }

        if (dlp.matches.length > 0) {
          metrics.redacted_total += dlp.matches.length;
        }

        const redactedBody = dlp.body;
        const isStream = redactedBody.stream === true;
        const useAgentLoop =
          config.agentLoop.enabled &&
          typeof redactedBody.metadata === "object" &&
          redactedBody.metadata !== null &&
          (redactedBody.metadata as Record<string, unknown>).agent_loop === true;

        auditEvent(config.audit.dir, {
          reqId,
          clientIp: ip,
          phase: "request",
          model: redactedBody.model,
          bytesIn: rawBody.length,
          dlpMatches: summarizeMatches(dlp.matches),
          blocked: false,
        });

        if (useAgentLoop) {
          try {
            const result = await runAgentLoop(redactedBody, {
              config,
              upstream: upstreamClient,
              tools,
              patterns,
              auditDir: config.audit.dir,
              reqId,
            });
            metrics.tool_calls_total += 1;
            writeJson(res, 200, result);
            auditEvent(config.audit.dir, {
              reqId,
              phase: "response",
              model: result.model,
              bytesOut: Buffer.byteLength(JSON.stringify(result)),
              latencyMs: Date.now() - started,
            });
          } catch (err) {
            metrics.errors_total += 1;
            writeJson(res, 502, {
              error: { type: "agent_loop_error", message: String(err) },
            });
            auditEvent(config.audit.dir, {
              reqId,
              phase: "error",
              error: String(err),
              latencyMs: Date.now() - started,
            });
          }
          return;
        }

        // Forward to real upstream
        const upstreamUrl = `${upstreamBaseUrl.replace(/\/$/, "")}/v1/messages`;
        const upstreamCheck = validateUpstreamUrl(
          upstreamUrl,
          config.allowlist,
          upstreamBaseUrl,
        );
        if (!upstreamCheck.allowed) {
          metrics.errors_total += 1;
          writeJson(res, 500, {
            error: {
              type: "upstream_blocked",
              message: upstreamCheck.reason,
            },
          });
          return;
        }

        let upstreamResp: Response;
        try {
          upstreamResp = await fetch(upstreamUrl, {
            method: "POST",
            headers: {
              "content-type": "application/json",
              "x-api-key": apiKey,
              "anthropic-version": "2023-06-01",
              accept: isStream ? "text/event-stream" : "application/json",
            },
            body: JSON.stringify(redactedBody),
          });
        } catch (err) {
          metrics.errors_total += 1;
          writeJson(res, 502, {
            error: { type: "upstream_fetch_error", message: String(err) },
          });
          auditEvent(config.audit.dir, {
            reqId,
            phase: "error",
            error: String(err),
            latencyMs: Date.now() - started,
          });
          return;
        }

        if (isStream) {
          res.writeHead(upstreamResp.status, {
            "content-type": "text/event-stream",
            "cache-control": "no-cache",
            connection: "keep-alive",
          });
          if (!upstreamResp.body) {
            res.end();
            return;
          }
          const reader = upstreamResp.body.getReader();
          const decoder = new TextDecoder();
          let buffer = "";
          let bytesOut = 0;
          let streamRedacted = 0;
          let streamBlocked = false;
          try {
            for (;;) {
              const { done, value } = await reader.read();
              if (done) break;
              buffer += decoder.decode(value, { stream: true });
              // flush by SSE events (double newline)
              let idx: number;
              while ((idx = buffer.indexOf("\n\n")) !== -1) {
                const rawEvent = buffer.slice(0, idx);
                buffer = buffer.slice(idx + 2);
                const filtered = redactStreamingChunk(rawEvent, patterns);
                if (filtered.blocked) streamBlocked = true;
                streamRedacted += filtered.matches.length;
                const outChunk = filtered.output + "\n\n";
                bytesOut += Buffer.byteLength(outChunk);
                res.write(outChunk);
              }
            }
            if (buffer.length > 0) {
              const filtered = redactStreamingChunk(buffer, patterns);
              if (filtered.blocked) streamBlocked = true;
              streamRedacted += filtered.matches.length;
              bytesOut += Buffer.byteLength(filtered.output);
              res.write(filtered.output);
            }
          } finally {
            res.end();
          }
          metrics.redacted_total += streamRedacted;
          if (streamBlocked) metrics.blocked_total += 1;
          auditEvent(config.audit.dir, {
            reqId,
            phase: "response",
            model: redactedBody.model,
            bytesOut,
            latencyMs: Date.now() - started,
            meta: {
              stream: true,
              streamRedacted,
              streamBlocked,
            },
          });
          return;
        }

        const respText = await upstreamResp.text();
        res.writeHead(upstreamResp.status, {
          "content-type": upstreamResp.headers.get("content-type") ?? "application/json",
        });
        res.end(respText);
        auditEvent(config.audit.dir, {
          reqId,
          phase: "response",
          model: redactedBody.model,
          bytesOut: Buffer.byteLength(respText),
          latencyMs: Date.now() - started,
        });
        return;
      }

      writeJson(res, 404, { error: { type: "not_found" } });
    } catch (err) {
      metrics.errors_total += 1;
      try {
        writeJson(res, 500, {
          error: { type: "internal", message: String(err) },
        });
      } catch {
        // already sent; nothing to do
      }
      auditEvent(config.audit.dir, {
        reqId,
        phase: "error",
        error: String(err),
        latencyMs: Date.now() - started,
      });
    }
  });

  const port = await new Promise<number>((resolve, reject) => {
    server.once("error", reject);
    server.listen(config.listen.port, host, () => {
      const addr = server.address();
      if (addr && typeof addr === "object") resolve(addr.port);
      else reject(new Error("Failed to resolve listen port"));
    });
  });

  return {
    port,
    host,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }),
    metrics: () => ({ ...metrics }),
  };
}

export type { Server };
