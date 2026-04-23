/**
 * AI Egress Proxy — configuration loader.
 *
 * Loads a JSONC config from ~/.config/omc/proxy.jsonc (or an explicit path),
 * merges in env overrides (OMC_PROXY_*), and validates against a Zod schema.
 */

import { readFileSync, existsSync } from "fs";
import { homedir } from "os";
import { join } from "path";
import { z } from "zod";
import safeRegexDefault from "safe-regex";
import { parseJsonc } from "../utils/jsonc.js";

// safe-regex is CJS and exported as default function.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const safeRegex: (re: RegExp | string) => boolean = safeRegexDefault as any;

const DlpPatternSchema = z.object({
  name: z.string().min(1),
  regex: z.string().min(1),
  policy: z.enum(["block", "redact", "tokenize"]),
  replacement: z.string().optional(),
});

const DictionaryEntrySchema = z.object({
  term: z.string().min(1),
  classifier: z.string().min(1),
  policy: z.enum(["block", "redact", "tokenize"]),
  tenantId: z.string().optional(),
});

export const ProxyConfigSchema = z.object({
  listen: z.object({
    host: z.string().default("127.0.0.1"),
    port: z.number().int().min(1).max(65535).default(11434),
  }),
  upstream: z.object({
    baseUrl: z.string().url().default("https://api.anthropic.com"),
    apiKeyEnv: z.string().min(1).default("ANTHROPIC_API_KEY"),
  }),
  dlp: z.object({
    patterns: z.array(DlpPatternSchema).default([]),
    customDenyTerms: z.array(z.string()).default([]),
  }),
  allowlist: z.object({
    mcpTools: z.array(z.string()).default([]),
    urlDomains: z.array(z.string()).default([]),
    pathPrefixes: z.array(z.string()).default([]),
  }),
  hitl: z.object({
    enabled: z.boolean().default(false),
    sensitiveTools: z.array(z.string()).default([]),
    timeoutMs: z.number().int().positive().default(60_000),
  }),
  audit: z.object({
    dir: z.string().default(join(homedir(), ".omc", "proxy", "audit")),
    maxBodyBytes: z.number().int().positive().default(1_000_000),
  }),
  agentLoop: z.object({
    enabled: z.boolean().default(false),
    maxIterations: z.number().int().positive().default(5),
    maxToolOutputBytes: z.number().int().positive().default(100_000),
  }),
  auth: z.object({
    tokenEnv: z.string().min(1).default("OMC_PROXY_CLIENT_TOKEN"),
  }),
  vault: z
    .object({
      ttlSeconds: z.number().int().positive().default(86400),
    })
    .default({ ttlSeconds: 86400 }),
  dictionary: z
    .object({
      path: z.string().optional(),
      entries: z.array(DictionaryEntrySchema).default([]),
    })
    .default({ entries: [] }),
  conversation: z
    .object({
      headerName: z.string().min(1).default("X-OMC-Conversation-Id"),
    })
    .default({ headerName: "X-OMC-Conversation-Id" }),
});

export type DlpPattern = z.infer<typeof DlpPatternSchema>;
export type DictionaryEntryConfig = z.infer<typeof DictionaryEntrySchema>;
export type ProxyConfig = z.infer<typeof ProxyConfigSchema>;

export const DEFAULT_CONFIG: ProxyConfig = ProxyConfigSchema.parse({
  listen: { host: "127.0.0.1", port: 11434 },
  upstream: {
    baseUrl: "https://api.anthropic.com",
    apiKeyEnv: "ANTHROPIC_API_KEY",
  },
  dlp: {
    patterns: [
      {
        name: "email",
        regex: "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}",
        policy: "redact",
      },
      {
        name: "phone_intl",
        regex: "\\+\\d{1,3}[ .-]?\\d{2,4}[ .-]?\\d{3,4}[ .-]?\\d{3,4}",
        policy: "redact",
      },
      {
        name: "phone_vn",
        regex: "\\b0(?:3|5|7|8|9)\\d{8}\\b",
        policy: "redact",
      },
      {
        name: "jwt",
        regex:
          "eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}",
        policy: "block",
      },
      {
        name: "aws_access_key",
        regex: "\\b(?:AKIA|ASIA)[A-Z0-9]{16}\\b",
        policy: "block",
      },
      {
        name: "private_key",
        regex: "-----BEGIN (RSA|OPENSSH|EC|PGP|DSA) PRIVATE KEY-----",
        policy: "block",
      },
      {
        name: "generic_api_key",
        regex: "sk-[A-Za-z0-9_-]{20,}",
        policy: "block",
      },
      {
        name: "github_token",
        regex: "gh[pousr]_[A-Za-z0-9]{30,}",
        policy: "block",
      },
      {
        name: "cccd_vn",
        regex: "\\b\\d{12}\\b",
        policy: "redact",
      },
    ],
    customDenyTerms: [],
  },
  allowlist: {
    mcpTools: ["echo", "read_file"],
    urlDomains: ["api.anthropic.com"],
    pathPrefixes: [join(homedir(), ".omc", "proxy", "allowed")],
  },
  hitl: {
    enabled: false,
    sensitiveTools: [],
    timeoutMs: 60_000,
  },
  audit: {
    dir: join(homedir(), ".omc", "proxy", "audit"),
    maxBodyBytes: 1_000_000,
  },
  agentLoop: {
    enabled: false,
    maxIterations: 5,
    maxToolOutputBytes: 100_000,
  },
  auth: {
    tokenEnv: "OMC_PROXY_CLIENT_TOKEN",
  },
  vault: {
    ttlSeconds: 86400,
  },
  dictionary: {
    entries: [],
  },
  conversation: {
    headerName: "X-OMC-Conversation-Id",
  },
});

export function defaultConfigPath(): string {
  return join(homedir(), ".config", "omc", "proxy.jsonc");
}

function deepMerge<T>(target: T, source: Partial<T> | undefined): T {
  if (!source) return target;
  if (
    typeof target !== "object" ||
    target === null ||
    Array.isArray(target) ||
    typeof source !== "object" ||
    source === null ||
    Array.isArray(source)
  ) {
    return (source as T) ?? target;
  }
  const out: Record<string, unknown> = { ...(target as Record<string, unknown>) };
  for (const [k, v] of Object.entries(source)) {
    if (k === "__proto__" || k === "constructor" || k === "prototype") continue;
    const tv = (target as Record<string, unknown>)[k];
    if (
      v !== null &&
      typeof v === "object" &&
      !Array.isArray(v) &&
      tv !== null &&
      typeof tv === "object" &&
      !Array.isArray(tv)
    ) {
      out[k] = deepMerge(tv, v as Partial<typeof tv>);
    } else if (v !== undefined) {
      out[k] = v;
    }
  }
  return out as T;
}

function envOverrides(): Partial<ProxyConfig> {
  const out: Record<string, unknown> = {};
  const listen: Record<string, unknown> = {};
  if (process.env.OMC_PROXY_HOST) listen.host = process.env.OMC_PROXY_HOST;
  if (process.env.OMC_PROXY_PORT) {
    const p = parseInt(process.env.OMC_PROXY_PORT, 10);
    if (Number.isFinite(p)) listen.port = p;
  }
  if (Object.keys(listen).length > 0) out.listen = listen;

  const upstream: Record<string, unknown> = {};
  if (process.env.OMC_PROXY_UPSTREAM)
    upstream.baseUrl = process.env.OMC_PROXY_UPSTREAM;
  if (process.env.OMC_PROXY_API_KEY_ENV)
    upstream.apiKeyEnv = process.env.OMC_PROXY_API_KEY_ENV;
  if (Object.keys(upstream).length > 0) out.upstream = upstream;

  const audit: Record<string, unknown> = {};
  if (process.env.OMC_PROXY_AUDIT_DIR)
    audit.dir = process.env.OMC_PROXY_AUDIT_DIR;
  if (Object.keys(audit).length > 0) out.audit = audit;

  const agentLoop: Record<string, unknown> = {};
  if (process.env.OMC_PROXY_AGENT_LOOP !== undefined) {
    agentLoop.enabled = process.env.OMC_PROXY_AGENT_LOOP === "1";
  }
  if (Object.keys(agentLoop).length > 0) out.agentLoop = agentLoop;

  return out as Partial<ProxyConfig>;
}

export interface CompiledPattern {
  name: string;
  regex: RegExp;
  policy: "block" | "redact" | "tokenize";
  replacement?: string;
}

export function compileConfigPatterns(cfg: ProxyConfig): CompiledPattern[] {
  const out: CompiledPattern[] = [];
  for (const p of cfg.dlp.patterns) {
    if (!safeRegex(p.regex)) {
      throw new Error(
        `DLP pattern '${p.name}' rejected by safe-regex (potential ReDoS)`,
      );
    }
    try {
      out.push({
        name: p.name,
        regex: new RegExp(p.regex, "g"),
        policy: p.policy,
        replacement: p.replacement,
      });
    } catch (err) {
      throw new Error(`DLP pattern '${p.name}' failed to compile: ${String(err)}`);
    }
  }
  for (const term of cfg.dlp.customDenyTerms) {
    const escaped = term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    if (!safeRegex(escaped)) {
      throw new Error(
        `Custom deny term '${term}' rejected by safe-regex (potential ReDoS)`,
      );
    }
    out.push({
      name: `deny_term:${term}`,
      regex: new RegExp(escaped, "gi"),
      policy: "block",
    });
  }
  return out;
}

export function loadConfig(path?: string): ProxyConfig {
  const target = path ?? defaultConfigPath();
  let fileConfig: Partial<ProxyConfig> = {};
  if (existsSync(target)) {
    try {
      const raw = readFileSync(target, "utf-8");
      fileConfig = parseJsonc(raw) as Partial<ProxyConfig>;
    } catch (err) {
      throw new Error(`Failed to parse proxy config '${target}': ${String(err)}`);
    }
  }
  const merged = deepMerge(DEFAULT_CONFIG, fileConfig);
  const withEnv = deepMerge(merged, envOverrides());
  return ProxyConfigSchema.parse(withEnv);
}

export function redactConfigSecrets(cfg: ProxyConfig): ProxyConfig {
  // No secrets live in config (keys come from env). Return shallow copy
  // defensively so callers cannot mutate our constant.
  return JSON.parse(JSON.stringify(cfg)) as ProxyConfig;
}
