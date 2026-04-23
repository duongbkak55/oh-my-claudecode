import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { createServer, type Server, type IncomingMessage, type ServerResponse } from "http";
import { mkdtempSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { AddressInfo } from "net";
import { DEFAULT_CONFIG, type ProxyConfig } from "../config.js";
import { startProxy, type StartedProxy } from "../server.js";

const AUTH: Record<string, string> = {
  authorization: "Bearer test-client-token",
};

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
    process.env.OMC_PROXY_CLIENT_TOKEN = "test-client-token";
    // Mock upstream uses http://127.0.0.1:<port>, so allow http here only.
    process.env.OMC_PROXY_ALLOW_HTTP_UPSTREAM = "1";
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

    const m1 = await (
      await fetch(`http://127.0.0.1:${proxy.port}/metrics`, { headers: AUTH })
    ).text();
    expect(m1).toMatch(/omc_proxy_requests_total 0/);

    await fetch(`http://127.0.0.1:${proxy.port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", ...AUTH },
      body: JSON.stringify({
        model: "claude-test",
        messages: [{ role: "user", content: "Hello world" }],
      }),
    });

    const m2 = await (
      await fetch(`http://127.0.0.1:${proxy.port}/metrics`, { headers: AUTH })
    ).text();
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
      headers: { "content-type": "application/json", ...AUTH },
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
      headers: { "content-type": "application/json", ...AUTH },
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
      headers: { "content-type": "application/json", ...AUTH },
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
      headers: { "content-type": "application/json", ...AUTH },
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

  describe("bearer-token auth", () => {
    it("returns 401 when Authorization header is missing", async () => {
      proxy = await startProxy({ config: baseConfig(auditDir) });
      const r = await fetch(`http://127.0.0.1:${proxy.port}/v1/messages`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ messages: [] }),
      });
      expect(r.status).toBe(401);
      const body = (await r.json()) as { error: string };
      expect(body.error).toBe("unauthorized");
    });

    it("returns 401 when Authorization token is wrong", async () => {
      proxy = await startProxy({ config: baseConfig(auditDir) });
      const r = await fetch(`http://127.0.0.1:${proxy.port}/v1/messages`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: "Bearer not-the-right-token",
        },
        body: JSON.stringify({ messages: [] }),
      });
      expect(r.status).toBe(401);
    });

    it("returns 200 on /v1/messages with correct token", async () => {
      upstream = await createMockUpstream((_req, res) => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            id: "msg_1",
            role: "assistant",
            model: "claude-test",
            content: [{ type: "text", text: "hi" }],
          }),
        );
      });
      proxy = await startProxy({
        config: baseConfig(auditDir),
        upstreamBaseUrlOverride: upstream.url,
      });
      const r = await fetch(`http://127.0.0.1:${proxy.port}/v1/messages`, {
        method: "POST",
        headers: { "content-type": "application/json", ...AUTH },
        body: JSON.stringify({
          model: "claude-test",
          messages: [{ role: "user", content: "hello" }],
        }),
      });
      expect(r.status).toBe(200);
    });

    it("returns 503 when client-token env is NOT set", async () => {
      delete process.env.OMC_PROXY_CLIENT_TOKEN;
      proxy = await startProxy({ config: baseConfig(auditDir) });
      const r = await fetch(`http://127.0.0.1:${proxy.port}/v1/messages`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ messages: [] }),
      });
      expect(r.status).toBe(503);
      const body = (await r.json()) as { error: string };
      expect(body.error).toMatch(/auth/);
    });

    it("/health is open (no auth required)", async () => {
      proxy = await startProxy({ config: baseConfig(auditDir) });
      const r = await fetch(`http://127.0.0.1:${proxy.port}/health`);
      expect(r.status).toBe(200);
    });

    it("/metrics requires auth (401 without header)", async () => {
      proxy = await startProxy({ config: baseConfig(auditDir) });
      const r = await fetch(`http://127.0.0.1:${proxy.port}/metrics`);
      expect(r.status).toBe(401);
    });
  });

  describe("tokenize + detokenize round-trip", () => {
    function tokenizingConfig(auditDir: string): ProxyConfig {
      const base = baseConfig(auditDir);
      return {
        ...base,
        dlp: {
          patterns: [
            {
              name: "email",
              regex: "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}",
              policy: "tokenize",
            },
          ],
          customDenyTerms: [],
        },
        dictionary: {
          entries: [
            {
              term: "Vietcombank",
              classifier: "PARTNER_NAME",
              policy: "tokenize",
            },
          ],
        },
      };
    }

    it("email round-trip: client -> token to upstream -> original back to client", async () => {
      let upstreamSawToken: string | null = null;
      upstream = await createMockUpstream((req, res) => {
        let data = "";
        req.on("data", (c: Buffer) => (data += c.toString("utf-8")));
        req.on("end", () => {
          const parsed = JSON.parse(data) as {
            messages: Array<{ content: string }>;
          };
          const content = parsed.messages[0]!.content;
          const m = content.match(/EMAIL_\d{2,3}/);
          upstreamSawToken = m ? m[0] : null;
          res.writeHead(200, { "content-type": "application/json" });
          res.end(
            JSON.stringify({
              id: "msg_r1",
              role: "assistant",
              model: "claude-test",
              content: [
                {
                  type: "text",
                  text: `ok, I'll contact ${upstreamSawToken ?? ""} shortly`,
                },
              ],
            }),
          );
        });
      });
      proxy = await startProxy({
        config: tokenizingConfig(auditDir),
        upstreamBaseUrlOverride: upstream.url,
      });
      const r = await fetch(`http://127.0.0.1:${proxy.port}/v1/messages`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...AUTH,
          "x-omc-conversation-id": "conv-round-trip",
        },
        body: JSON.stringify({
          model: "claude-test",
          messages: [
            { role: "user", content: "please email alice@example.com" },
          ],
        }),
      });
      expect(r.status).toBe(200);
      expect(upstreamSawToken).not.toBeNull();
      expect(upstreamSawToken).toMatch(/^EMAIL_\d{2,3}$/);
      const body = (await r.json()) as {
        content: Array<{ text: string }>;
      };
      expect(body.content[0]!.text).toContain("alice@example.com");
      expect(body.content[0]!.text).not.toContain("EMAIL_0");
    });

    it("dictionary hit Vietcombank is tokenized on request and restored on response", async () => {
      let upstreamPayload = "";
      upstream = await createMockUpstream((req, res) => {
        let data = "";
        req.on("data", (c: Buffer) => (data += c.toString("utf-8")));
        req.on("end", () => {
          upstreamPayload = data;
          // echo the Vietcombank token back
          const parsed = JSON.parse(data) as {
            messages: Array<{ content: string }>;
          };
          const content = parsed.messages[0]!.content;
          const m = content.match(/PARTNER_NAME_\d{2,3}/);
          const echo = m ? m[0] : "NONE";
          res.writeHead(200, { "content-type": "application/json" });
          res.end(
            JSON.stringify({
              id: "msg_v1",
              role: "assistant",
              model: "claude-test",
              content: [
                { type: "text", text: `Working with ${echo} folks.` },
              ],
            }),
          );
        });
      });
      proxy = await startProxy({
        config: tokenizingConfig(auditDir),
        upstreamBaseUrlOverride: upstream.url,
      });
      const r = await fetch(`http://127.0.0.1:${proxy.port}/v1/messages`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...AUTH,
          "x-omc-conversation-id": "conv-dict",
        },
        body: JSON.stringify({
          model: "claude-test",
          messages: [
            {
              role: "user",
              content: "Integrate with Vietcombank as soon as possible.",
            },
          ],
        }),
      });
      expect(r.status).toBe(200);
      expect(upstreamPayload).not.toContain("Vietcombank");
      expect(upstreamPayload).toMatch(/PARTNER_NAME_\d{2,3}/);
      const body = (await r.json()) as {
        content: Array<{ text: string }>;
      };
      expect(body.content[0]!.text).toContain("Vietcombank");
      expect(body.content[0]!.text).not.toContain("PARTNER_NAME_");
    });

    it("X-OMC-Conversation-Id header groups tokens across requests", async () => {
      const sawTokens: string[] = [];
      upstream = await createMockUpstream((req, res) => {
        let data = "";
        req.on("data", (c: Buffer) => (data += c.toString("utf-8")));
        req.on("end", () => {
          const m = data.match(/EMAIL_\d{2,3}/g);
          if (m) for (const t of m) sawTokens.push(t);
          res.writeHead(200, { "content-type": "application/json" });
          res.end(
            JSON.stringify({
              id: "msg_c",
              role: "assistant",
              model: "claude-test",
              content: [{ type: "text", text: "ok" }],
            }),
          );
        });
      });
      proxy = await startProxy({
        config: tokenizingConfig(auditDir),
        upstreamBaseUrlOverride: upstream.url,
      });
      const hdr = {
        "content-type": "application/json",
        ...AUTH,
        "x-omc-conversation-id": "conv-shared",
      };
      await fetch(`http://127.0.0.1:${proxy.port}/v1/messages`, {
        method: "POST",
        headers: hdr,
        body: JSON.stringify({
          model: "claude-test",
          messages: [{ role: "user", content: "mail alice@example.com" }],
        }),
      });
      await fetch(`http://127.0.0.1:${proxy.port}/v1/messages`, {
        method: "POST",
        headers: hdr,
        body: JSON.stringify({
          model: "claude-test",
          messages: [{ role: "user", content: "again alice@example.com" }],
        }),
      });
      expect(sawTokens.length).toBeGreaterThanOrEqual(2);
      // Same value in same conversation must issue the same token.
      expect(sawTokens[0]).toBe(sawTokens[1]);
    });

    it("system prompt contains the DLP preservation instruction", async () => {
      let upstreamSystem: unknown = undefined;
      upstream = await createMockUpstream((req, res) => {
        let data = "";
        req.on("data", (c: Buffer) => (data += c.toString("utf-8")));
        req.on("end", () => {
          const parsed = JSON.parse(data) as { system?: unknown };
          upstreamSystem = parsed.system;
          res.writeHead(200, { "content-type": "application/json" });
          res.end(
            JSON.stringify({
              id: "msg_s",
              role: "assistant",
              model: "claude-test",
              content: [{ type: "text", text: "k" }],
            }),
          );
        });
      });
      proxy = await startProxy({
        config: tokenizingConfig(auditDir),
        upstreamBaseUrlOverride: upstream.url,
      });
      await fetch(`http://127.0.0.1:${proxy.port}/v1/messages`, {
        method: "POST",
        headers: { "content-type": "application/json", ...AUTH },
        body: JSON.stringify({
          model: "claude-test",
          system: "You are helpful.",
          messages: [
            { role: "user", content: "mail alice@example.com now" },
          ],
        }),
      });
      const s =
        typeof upstreamSystem === "string"
          ? upstreamSystem
          : JSON.stringify(upstreamSystem);
      expect(s).toContain("[OMC-DLP]");
    });
  });

  it("does NOT leak an sk-ant secret split across SSE frames", async () => {
    upstream = await createMockUpstream((_req, res) => {
      res.writeHead(200, {
        "content-type": "text/event-stream",
        "cache-control": "no-cache",
      });
      const frames = [
        "sk-",
        "ant-",
        "abcdefghijklmnopqrstuvwxyz1234567890ZZZZ",
      ];
      for (const text of frames) {
        res.write(
          `event: content_block_delta\n` +
            `data: ${JSON.stringify({
              type: "content_block_delta",
              index: 0,
              delta: { type: "text_delta", text },
            })}\n\n`,
        );
      }
      res.end();
    });
    proxy = await startProxy({
      config: baseConfig(auditDir),
      upstreamBaseUrlOverride: upstream.url,
    });
    const r = await fetch(`http://127.0.0.1:${proxy.port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", ...AUTH },
      body: JSON.stringify({
        model: "claude-test",
        stream: true,
        messages: [{ role: "user", content: "tell me something" }],
      }),
    });
    const text = await r.text();
    expect(text).not.toContain(
      "sk-ant-abcdefghijklmnopqrstuvwxyz1234567890",
    );
    // Should include a dlp_blocked error frame.
    expect(text).toContain("dlp_blocked");
  });
});
