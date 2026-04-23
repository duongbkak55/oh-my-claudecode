/**
 * Allowlist enforcement for outbound tool calls and URLs.
 */

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
  for (const prefix of prefixes) {
    if (!prefix) continue;
    if (p === prefix || p.startsWith(prefix.endsWith("/") ? prefix : `${prefix}/`)) {
      return true;
    }
  }
  return false;
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
  for (const key of ["url", "endpoint"] as const) {
    const v = input[key];
    if (typeof v === "string" && v.length > 0) {
      const ssrf = validateUrlForSSRF(v);
      if (!ssrf.allowed) {
        return {
          allowed: false,
          reason: `Tool '${call.name}' ${key} blocked by SSRF guard: ${ssrf.reason ?? "unknown"}`,
        };
      }
      let parsed: URL;
      try {
        parsed = new URL(v);
      } catch {
        return { allowed: false, reason: `Tool '${call.name}' ${key} is not a valid URL` };
      }
      if (!domainMatches(parsed.hostname, allowlist.urlDomains)) {
        return {
          allowed: false,
          reason: `Tool '${call.name}' ${key} host '${parsed.hostname}' not in urlDomains allowlist`,
        };
      }
    }
  }
  for (const key of ["path", "file_path"] as const) {
    const v = input[key];
    if (typeof v === "string" && v.length > 0) {
      if (!pathAllowed(v, allowlist.pathPrefixes)) {
        return {
          allowed: false,
          reason: `Tool '${call.name}' ${key} '${v}' not under pathPrefixes allowlist`,
        };
      }
    }
  }
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
