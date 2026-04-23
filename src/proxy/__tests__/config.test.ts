import { describe, it, expect, afterEach, beforeEach } from "vitest";
import { mkdtempSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import {
  DEFAULT_CONFIG,
  ProxyConfigSchema,
  compileConfigPatterns,
  loadConfig,
} from "../config.js";

describe("ProxyConfig defaults", () => {
  it("default config validates against schema", () => {
    expect(() => ProxyConfigSchema.parse(DEFAULT_CONFIG)).not.toThrow();
  });

  it("default patterns compile without throwing", () => {
    expect(() => compileConfigPatterns(DEFAULT_CONFIG)).not.toThrow();
  });
});

describe("loadConfig env overrides", () => {
  const originalEnv = { ...process.env };
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "omc-proxy-cfg-"));
  });
  afterEach(() => {
    process.env = { ...originalEnv };
  });

  it("env OMC_PROXY_PORT overrides port", () => {
    process.env.OMC_PROXY_PORT = "23456";
    const cfg = loadConfig(join(dir, "does-not-exist.jsonc"));
    expect(cfg.listen.port).toBe(23456);
  });

  it("env OMC_PROXY_UPSTREAM overrides baseUrl", () => {
    process.env.OMC_PROXY_UPSTREAM = "https://proxy.example.com";
    const cfg = loadConfig(join(dir, "does-not-exist.jsonc"));
    expect(cfg.upstream.baseUrl).toBe("https://proxy.example.com");
  });

  it("file config overrides default but env overrides file", () => {
    const path = join(dir, "proxy.jsonc");
    writeFileSync(
      path,
      JSON.stringify({
        listen: { port: 12345 },
        upstream: { baseUrl: "https://file.example.com" },
      }),
    );
    process.env.OMC_PROXY_UPSTREAM = "https://env.example.com";
    const cfg = loadConfig(path);
    expect(cfg.listen.port).toBe(12345);
    expect(cfg.upstream.baseUrl).toBe("https://env.example.com");
  });
});

describe("compileConfigPatterns rejects ReDoS", () => {
  it("throws when a custom pattern is ReDoS-prone", () => {
    const bad = {
      ...DEFAULT_CONFIG,
      dlp: {
        patterns: [
          { name: "bad", regex: "(a+)+$", policy: "redact" as const },
        ],
        customDenyTerms: [],
      },
    };
    expect(() => compileConfigPatterns(bad)).toThrow(/safe-regex/);
  });
});
