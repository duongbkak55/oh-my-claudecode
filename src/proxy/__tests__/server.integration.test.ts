import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { createServer, type Server, type IncomingMessage, type ServerResponse } from "http";
import { mkdtempSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { AddressInfo } from "net";
import { DEFAULT_CONFIG, type ProxyConfig } from "../config.js";
import { startProxy, type StartedProxy } from "../server.js";

async function createMockUpstream(
  handler: (req: IncomingMessage, res: ServerResponse) => void,
): Promise<{ url: string; close: () => Promise<void> }> {
  const server: Server = createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  return {
    url: `http://127.0.0.1:${port}`,
    close: () =>
      new Promise<void>((res, rej) =>
        server.close((err) => (err ? rej(err) : res())),
      ),
  };
}

function baseConfig(auditDir: string): ProxyConfig {
  return {
    ...DEFAULT_CONFIG,
    listen: { host: "127.0.0.1", port: 0 },
    audit: { dir: auditDir, maxBodyBytes: 1_000_000 },
    allowlist: {
      mcpTools: ["echo"],
      urlDomains: ["api.anthropic.com"],
      pathPrefixes: [],
    },
  };
}

describe("proxy server integration", () => {
  let proxy: StartedProxy | null = null;
  let upstream: { url: string; close: () => Promise<void> } | null = null;
  let auditDir: string;
  const originalEnv = { ...process.env };

  beforeEach(() => {
    auditDir = mkdtempSync(join(tmpdir(), "omc-proxy-int-"));
    process.env.ANTHROPIC_API_KEY = "test-key";
  });

  afterEach(async () => {
    if (proxy) {
      await proxy.close();
      proxy = null;
    }
    if (upstream) {
      await upstream.close();
      upstream = null;
    }
    process.env = { ...originalEnv };
  });

  it("GET /health returns 200 ok", async () => {
    proxy = await startProxy({ config: baseConfig(auditDir) });
    const r = await fetch(`http://127.0.0.1:${proxy.port}/health`);
    expect(r.status).toBe(200);
    const body = (await r.json()) as { status: string };
    expect(body.status).toBe("ok");
  });

  it("GET /metrics includes counters and requests_total increments", async () => {
    upstream = await createMockUpstream((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          id: "msg_1",
          role: "assistant",
          content: [{ type: "text", text: "hello" }],
        }),
      );
    });
    proxy = await startProxy({
      config: baseConfig(auditDir),
      upstreamBaseUrlOverride: upstream.url,
    });

    const m1 = await (await fetch(`http://127.0.0.1:${proxy.port}/metrics`)).text();
    expect(m1).toMatch(/omc_proxy_requests_total 0/);

    await fetch(`http://127.0.0.1:${proxy.port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        model: "claude-test",
        messages: [{ role: "user", content: "Hello world" }],
      }),
    });

    const m2 = await (await fetch(`http://127.0.0.1:${proxy.port}/metrics`)).text();
    expect(m2).toMatch(/omc_proxy_requests_total 1/);
  });

  it("blocks request containing API key pattern (400 dlp_blocked)", async () => {
    upstream = await createMockUpstream(() => {
      throw new Error("upstream should not be called when blocked");
    });
    proxy = await startProxy({
      config: baseConfig(auditDir),
      upstreamBaseUrlOverride: upstream.url,
    });
    const r = await fetch(`http://127.0.0.1:${proxy.port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        model: "claude-test",
        messages: [
          {
            role: "user",
            content:
              "My key is sk-ant-FAKE_SECRET_KEY_abc123xyz0000000000 please use it",
          },
        ],
      }),
    });
    expect(r.status).toBe(400);
    const body = (await r.json()) as { error: { type: string; matches: string[] } };
    expect(body.error.type).toBe("dlp_blocked");
    expect(body.error.matches).toContain("generic_api_key");
  });

  it("redacts email and forwards request to upstream", async () => {
    let received: string | null = null;
    upstream = await createMockUpstream((req, res) => {
      let data = "";
      req.on("data", (c: Buffer) => (data += c.toString("utf-8")));
      req.on("end", () => {
        received = data;
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            id: "msg_2",
            role: "assistant",
            content: [{ type: "text", text: "ok" }],
          }),
        );
      });
    });
    proxy = await startProxy({
      config: baseConfig(auditDir),
      upstreamBaseUrlOverride: upstream.url,
    });
    const r = await fetch(`http://127.0.0.1:${proxy.port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        model: "claude-test",
        messages: [
          { role: "user", content: "email alice@example.com here" },
        ],
      }),
    });
    expect(r.status).toBe(200);
    expect(received).not.toBeNull();
    const parsed = JSON.parse(received!) as {
      messages: Array<{ content: unknown }>;
    };
    const content = parsed.messages[0]!.content;
    expect(typeof content === "string" ? content : "").toContain(
      "[REDACTED:email]",
    );
    expect(typeof content === "string" ? content : "").not.toContain(
      "alice@example.com",
    );
  });

  it("streams SSE and redacts email inside delta.text", async () => {
    upstream = await createMockUpstream((_req, res) => {
      res.writeHead(200, {
        "content-type": "text/event-stream",
        "cache-control": "no-cache",
      });
      const chunk =
        `event: content_block_delta\n` +
        `data: ${JSON.stringify({
          type: "content_block_delta",
          index: 0,
          delta: { type: "text_delta", text: "hi alice@example.com now" },
        })}\n\n`;
      res.write(chunk);
      res.end();
    });
    proxy = await startProxy({
      config: baseConfig(auditDir),
      upstreamBaseUrlOverride: upstream.url,
    });
    const r = await fetch(`http://127.0.0.1:${proxy.port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        model: "claude-test",
        stream: true,
        messages: [{ role: "user", content: "tell me something" }],
      }),
    });
    expect(r.status).toBe(200);
    const text = await r.text();
    expect(text).toContain("[REDACTED:email]");
    expect(text).not.toContain("alice@example.com");
  });

  it("returns 500 when upstream API key env var is missing", async () => {
    delete process.env.ANTHROPIC_API_KEY;
    proxy = await startProxy({ config: baseConfig(auditDir) });
    const r = await fetch(`http://127.0.0.1:${proxy.port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ messages: [] }),
    });
    expect(r.status).toBe(500);
    const body = (await r.json()) as { error: { type: string; message: string } };
    expect(body.error.type).toBe("config_error");
    expect(body.error.message).not.toContain("test-key");
  });

  it("refuses to bind to 0.0.0.0 without OMC_PROXY_ALLOW_PUBLIC=1", async () => {
    const cfg = baseConfig(auditDir);
    cfg.listen = { host: "0.0.0.0", port: 0 };
    delete process.env.OMC_PROXY_ALLOW_PUBLIC;
    await expect(startProxy({ config: cfg })).rejects.toThrow(
      /Refusing to bind/,
    );
  });
});
