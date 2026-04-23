/**
 * Allowlist enforcement for outbound tool calls and URLs.
 */

import * as fs from "fs";
import * as path from "path";
import { validateUrlForSSRF } from "../utils/ssrf-guard.js";
import type { ProxyConfig } from "./config.js";
import type { AnthropicRequestBody } from "./dlp.js";

export interface AllowlistCheck {
  allowed: boolean;
  reason?: string;
}

export interface ToolCall {
  name: string;
  input: Record<string, unknown> | undefined;
}

function domainMatches(host: string, allowed: string[]): boolean {
  const h = host.toLowerCase();
  for (const d of allowed) {
    const norm = d.toLowerCase().trim();
    if (!norm) continue;
    if (h === norm || h.endsWith(`.${norm}`)) return true;
  }
  return false;
}

function pathAllowed(p: string, prefixes: string[]): boolean {
  if (prefixes.length === 0) return false;
  // Resolve symlinks so callers can't bypass prefix with a symlink placed
  // inside an allowed prefix that points outside. If the path does not yet
  // exist we fall back to the lexical resolved form.
  let candidate: string;
  try {
    candidate = fs.realpathSync(path.resolve(p));
  } catch {
    candidate = path.resolve(p);
  }
  for (const prefix of prefixes) {
    if (!prefix) continue;
    let realPrefix: string;
    try {
      realPrefix = fs.realpathSync(path.resolve(prefix));
    } catch {
      realPrefix = path.resolve(prefix);
    }
    const trailing = realPrefix.endsWith(path.sep) ? realPrefix : `${realPrefix}${path.sep}`;
    if (candidate === realPrefix || candidate.startsWith(trailing)) {
      return true;
    }
  }
  return false;
}

function looksLikeUrl(s: string): boolean {
  // "entirely a URL" — reject leading/trailing whitespace, require scheme.
  if (!/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(s)) return false;
  try {
    // Also require no whitespace and that the parsed URL round-trips roughly.
    if (/\s/.test(s)) return false;
    new URL(s);
    return true;
  } catch {
    return false;
  }
}

function looksLikeAbsolutePath(s: string): boolean {
  return s.startsWith("/") || /^[A-Za-z]:[\\/]/.test(s);
}

function walkInputForBlockedRefs(
  value: unknown,
  allowlist: ProxyConfig["allowlist"],
  onBlock: (reason: string) => void,
  seen: Set<unknown> = new Set(),
): void {
  if (value === null || value === undefined) return;
  if (typeof value === "string") {
    if (value.length === 0) return;
    if (looksLikeUrl(value)) {
      const ssrf = validateUrlForSSRF(value);
      if (!ssrf.allowed) {
        onBlock(`URL '${value}' blocked by SSRF guard: ${ssrf.reason ?? "unknown"}`);
        return;
      }
      let parsed: URL;
      try {
        parsed = new URL(value);
      } catch {
        onBlock(`URL '${value}' is not a valid URL`);
        return;
      }
      if (!domainMatches(parsed.hostname, allowlist.urlDomains)) {
        onBlock(
          `URL host '${parsed.hostname}' not in urlDomains allowlist`,
        );
        return;
      }
    } else if (looksLikeAbsolutePath(value)) {
      if (!pathAllowed(value, allowlist.pathPrefixes)) {
        onBlock(`path '${value}' not under pathPrefixes allowlist`);
        return;
      }
    }
    return;
  }
  if (typeof value !== "object") return;
  if (seen.has(value)) return;
  seen.add(value);
  if (Array.isArray(value)) {
    for (const v of value) walkInputForBlockedRefs(v, allowlist, onBlock, seen);
    return;
  }
  for (const v of Object.values(value as Record<string, unknown>)) {
    walkInputForBlockedRefs(v, allowlist, onBlock, seen);
  }
}

export function validateToolCall(
  call: ToolCall,
  allowlist: ProxyConfig["allowlist"],
): AllowlistCheck {
  if (!call.name || typeof call.name !== "string") {
    return { allowed: false, reason: "Tool call has no name" };
  }
  if (!allowlist.mcpTools.includes(call.name)) {
    return {
      allowed: false,
      reason: `Tool '${call.name}' is not in mcpTools allowlist`,
    };
  }
  const input = call.input ?? {};
  let firstReason: string | undefined;
  walkInputForBlockedRefs(input, allowlist, (reason) => {
    if (!firstReason) firstReason = `Tool '${call.name}' ${reason}`;
  });
  if (firstReason) return { allowed: false, reason: firstReason };
  return { allowed: true };
}

export function validateUpstreamUrl(
  url: string,
  allowlist: ProxyConfig["allowlist"],
  upstreamBaseUrl: string,
): AllowlistCheck {
  const ssrf = validateUrlForSSRF(url);
  let upstreamHost: string | null = null;
  try {
    upstreamHost = new URL(upstreamBaseUrl).hostname.toLowerCase();
  } catch {
    upstreamHost = null;
  }
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return { allowed: false, reason: "Invalid URL" };
  }
  const host = parsed.hostname.toLowerCase();
  const allowHttp = process.env.OMC_PROXY_ALLOW_HTTP_UPSTREAM === "1";
  if (parsed.protocol !== "https:" && !allowHttp) {
    return {
      allowed: false,
      reason: `upstream must be https (got '${parsed.protocol}')`,
    };
  }
  if (upstreamHost && host === upstreamHost) {
    return { allowed: true };
  }
  if (!ssrf.allowed) {
    return { allowed: false, reason: ssrf.reason };
  }
  if (!domainMatches(host, allowlist.urlDomains)) {
    return {
      allowed: false,
      reason: `Host '${host}' not in urlDomains allowlist`,
    };
  }
  return { allowed: true };
}

export interface ToolScanResult {
  allowed: boolean;
  blocked: Array<{ name: string; reason: string }>;
}

export function scanRequestForBannedTools(
  body: AnthropicRequestBody,
  allowlist: ProxyConfig["allowlist"],
): ToolScanResult {
  const blocked: Array<{ name: string; reason: string }> = [];
  if (!Array.isArray(body.tools)) {
    return { allowed: true, blocked };
  }
  for (const tool of body.tools) {
    if (!tool || typeof tool.name !== "string") {
      blocked.push({ name: "<anonymous>", reason: "Tool definition has no name" });
      continue;
    }
    if (!allowlist.mcpTools.includes(tool.name)) {
      blocked.push({
        name: tool.name,
        reason: `Tool '${tool.name}' not in mcpTools allowlist`,
      });
    }
  }
  return { allowed: blocked.length === 0, blocked };
}
