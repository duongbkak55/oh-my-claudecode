import { describe, it, expect } from "vitest";
import {
  scanRequestForBannedTools,
  validateToolCall,
  validateUpstreamUrl,
} from "../allowlist.js";

const allowlist = {
  mcpTools: ["echo", "fetch_url"],
  urlDomains: ["api.anthropic.com", "example.com"],
  pathPrefixes: ["/tmp/allowed", "/home/user/ws"],
};

describe("validateToolCall", () => {
  it("allows known tools", () => {
    expect(
      validateToolCall({ name: "echo", input: { text: "hi" } }, allowlist)
        .allowed,
    ).toBe(true);
  });

  it("blocks unknown tool names", () => {
    const r = validateToolCall(
      { name: "evil_tool", input: {} },
      allowlist,
    );
    expect(r.allowed).toBe(false);
    expect(r.reason).toMatch(/mcpTools/);
  });

  it("blocks SSRF-private URL via url input", () => {
    const r = validateToolCall(
      { name: "fetch_url", input: { url: "http://127.0.0.1/" } },
      allowlist,
    );
    expect(r.allowed).toBe(false);
    expect(r.reason).toMatch(/SSRF/);
  });

  it("blocks URL whose domain is not allowlisted", () => {
    const r = validateToolCall(
      { name: "fetch_url", input: { url: "https://evil.net/foo" } },
      allowlist,
    );
    expect(r.allowed).toBe(false);
    expect(r.reason).toMatch(/urlDomains/);
  });

  it("allows URL with allowlisted subdomain", () => {
    const r = validateToolCall(
      { name: "fetch_url", input: { url: "https://sub.example.com/x" } },
      allowlist,
    );
    expect(r.allowed).toBe(true);
  });

  it("blocks file_path outside prefix allowlist", () => {
    const r = validateToolCall(
      { name: "echo", input: { file_path: "/etc/passwd" } },
      allowlist,
    );
    expect(r.allowed).toBe(false);
    expect(r.reason).toMatch(/pathPrefixes/);
  });

  it("allows file_path inside prefix", () => {
    const r = validateToolCall(
      { name: "echo", input: { file_path: "/tmp/allowed/x.txt" } },
      allowlist,
    );
    expect(r.allowed).toBe(true);
  });
});

describe("validateUpstreamUrl", () => {
  it("allows upstream host even if not in urlDomains", () => {
    const r = validateUpstreamUrl(
      "https://api.anthropic.com/v1/messages",
      { mcpTools: [], urlDomains: [], pathPrefixes: [] },
      "https://api.anthropic.com",
    );
    expect(r.allowed).toBe(true);
  });

  it("blocks private IPs for upstream", () => {
    const r = validateUpstreamUrl(
      "http://127.0.0.1/v1/messages",
      allowlist,
      "https://api.anthropic.com",
    );
    expect(r.allowed).toBe(false);
  });

  it("allows custom upstream with matching base URL host", () => {
    const r = validateUpstreamUrl(
      "https://proxy.example.com/v1/messages",
      allowlist,
      "https://proxy.example.com",
    );
    expect(r.allowed).toBe(true);
  });
});

describe("scanRequestForBannedTools", () => {
  it("returns blocked list for unknown tool definitions", () => {
    const r = scanRequestForBannedTools(
      {
        tools: [
          { name: "echo" },
          { name: "evil" },
        ],
      },
      allowlist,
    );
    expect(r.allowed).toBe(false);
    expect(r.blocked.map((b) => b.name)).toEqual(["evil"]);
  });

  it("is a no-op when no tools field present", () => {
    const r = scanRequestForBannedTools({}, allowlist);
    expect(r.allowed).toBe(true);
    expect(r.blocked.length).toBe(0);
  });
});
