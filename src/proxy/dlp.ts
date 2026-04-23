/**
 * DLP pipeline — scans text for sensitive patterns and applies block/redact
 * policy. Also provides helpers for Anthropic-shaped request bodies and SSE
 * streaming chunks.
 */

import safeRegexDefault from "safe-regex";
import type { CompiledPattern } from "./config.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const safeRegex: (re: RegExp | string) => boolean = safeRegexDefault as any;

export interface DlpMatch {
  patternName: string;
  policy: "block" | "redact";
  start: number;
  end: number;
  sample: string;
}

export interface DlpRawPattern {
  name: string;
  regex: string;
  policy: "block" | "redact";
  replacement?: string;
}

export function compilePatterns(raw: DlpRawPattern[]): CompiledPattern[] {
  const out: CompiledPattern[] = [];
  for (const p of raw) {
    if (!p.name || !p.regex) {
      throw new Error("Pattern missing name or regex");
    }
    if (!safeRegex(p.regex)) {
      throw new Error(
        `Pattern '${p.name}' rejected by safe-regex (potential ReDoS)`,
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
      throw new Error(`Pattern '${p.name}' failed to compile: ${String(err)}`);
    }
  }
  return out;
}

function maskSample(s: string): string {
  if (s.length <= 4) return "*".repeat(s.length);
  const head = s.slice(0, 2);
  const tail = s.slice(-2);
  const mid = "*".repeat(Math.min(8, Math.max(0, s.length - 4)));
  return `${head}${mid}${tail}`.slice(0, 12);
}

export function scan(text: string, patterns: CompiledPattern[]): DlpMatch[] {
  if (!text) return [];
  const matches: DlpMatch[] = [];
  const seen = new Set<string>();
  for (const p of patterns) {
    p.regex.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = p.regex.exec(text)) !== null) {
      const start = m.index;
      const end = start + m[0].length;
      const key = `${p.name}:${start}:${end}`;
      if (seen.has(key)) continue;
      seen.add(key);
      matches.push({
        patternName: p.name,
        policy: p.policy,
        start,
        end,
        sample: maskSample(m[0]),
      });
      if (m[0].length === 0) p.regex.lastIndex++;
    }
  }
  return matches;
}

export interface ApplyPolicyResult {
  output: string;
  matches: DlpMatch[];
  blocked: boolean;
}

export function applyPolicy(
  text: string,
  patterns: CompiledPattern[],
): ApplyPolicyResult {
  const matches = scan(text, patterns);
  const hasBlock = matches.some((m) => m.policy === "block");
  if (hasBlock) {
    return { output: text, matches, blocked: true };
  }
  const redacts = matches
    .filter((m) => m.policy === "redact")
    .sort((a, b) => a.start - b.start);
  if (redacts.length === 0) {
    return { output: text, matches, blocked: false };
  }
  // Walk in order, dropping overlaps.
  let out = "";
  let cursor = 0;
  for (const m of redacts) {
    if (m.start < cursor) continue;
    const replacement = findReplacement(patterns, m.patternName);
    out += text.slice(cursor, m.start);
    out += replacement ?? `[REDACTED:${m.patternName}]`;
    cursor = m.end;
  }
  out += text.slice(cursor);
  return { output: out, matches, blocked: false };
}

function findReplacement(
  patterns: CompiledPattern[],
  name: string,
): string | undefined {
  for (const p of patterns) {
    if (p.name === name) return p.replacement;
  }
  return undefined;
}

// --- Anthropic body walker -------------------------------------------------

export interface AnthropicContentBlock {
  type: string;
  text?: string;
  [k: string]: unknown;
}

export interface AnthropicMessage {
  role: string;
  content: string | AnthropicContentBlock[];
}

export interface AnthropicRequestBody {
  model?: string;
  system?: string | AnthropicContentBlock[];
  messages?: AnthropicMessage[];
  metadata?: Record<string, unknown>;
  tools?: Array<{ name: string; [k: string]: unknown }>;
  stream?: boolean;
  [k: string]: unknown;
}

export interface RedactRequestResult {
  body: AnthropicRequestBody;
  matches: DlpMatch[];
  blocked: boolean;
  blockedReasons: string[];
}

function redactString(
  s: string,
  patterns: CompiledPattern[],
  matches: DlpMatch[],
  reasons: Set<string>,
): { text: string; blocked: boolean } {
  const r = applyPolicy(s, patterns);
  for (const m of r.matches) {
    matches.push(m);
    if (m.policy === "block") reasons.add(m.patternName);
  }
  return { text: r.output, blocked: r.blocked };
}

export function redactAnthropicRequest(
  body: AnthropicRequestBody,
  patterns: CompiledPattern[],
): RedactRequestResult {
  const matches: DlpMatch[] = [];
  const reasons = new Set<string>();
  let blocked = false;

  // deep clone so we don't mutate the caller's object
  const clone = JSON.parse(JSON.stringify(body)) as AnthropicRequestBody;

  if (typeof clone.system === "string") {
    const r = redactString(clone.system, patterns, matches, reasons);
    clone.system = r.text;
    blocked = blocked || r.blocked;
  } else if (Array.isArray(clone.system)) {
    for (const block of clone.system) {
      if (block && typeof block.text === "string") {
        const r = redactString(block.text, patterns, matches, reasons);
        block.text = r.text;
        blocked = blocked || r.blocked;
      }
    }
  }

  if (Array.isArray(clone.messages)) {
    for (const msg of clone.messages) {
      if (typeof msg.content === "string") {
        const r = redactString(msg.content, patterns, matches, reasons);
        msg.content = r.text;
        blocked = blocked || r.blocked;
      } else if (Array.isArray(msg.content)) {
        for (const block of msg.content) {
          if (block && typeof block.text === "string") {
            const r = redactString(block.text, patterns, matches, reasons);
            block.text = r.text;
            blocked = blocked || r.blocked;
          }
        }
      }
    }
  }

  return {
    body: clone,
    matches,
    blocked,
    blockedReasons: Array.from(reasons),
  };
}

// --- SSE streaming chunk ---------------------------------------------------

/**
 * Redact a single SSE chunk (may contain multiple "event:" / "data:" lines).
 * Applies to `delta.text` on content_block_delta events. Anything that fails
 * to parse is forwarded unchanged to avoid breaking the stream.
 */
export function redactStreamingChunk(
  chunk: string,
  patterns: CompiledPattern[],
): { output: string; matches: DlpMatch[]; blocked: boolean } {
  const matches: DlpMatch[] = [];
  let blocked = false;
  const lines = chunk.split(/\r?\n/);
  const outLines: string[] = [];
  for (const line of lines) {
    if (!line.startsWith("data:")) {
      outLines.push(line);
      continue;
    }
    const payload = line.slice(5).trimStart();
    if (!payload || payload === "[DONE]") {
      outLines.push(line);
      continue;
    }
    try {
      const parsed = JSON.parse(payload) as {
        type?: string;
        delta?: { type?: string; text?: string };
      };
      if (
        parsed &&
        parsed.delta &&
        typeof parsed.delta.text === "string" &&
        parsed.delta.text.length > 0
      ) {
        const r = applyPolicy(parsed.delta.text, patterns);
        for (const m of r.matches) matches.push(m);
        if (r.blocked) {
          blocked = true;
          parsed.delta.text = "[BLOCKED:dlp]";
        } else {
          parsed.delta.text = r.output;
        }
        outLines.push(`data: ${JSON.stringify(parsed)}`);
      } else {
        outLines.push(line);
      }
    } catch {
      outLines.push(line);
    }
  }
  return { output: outLines.join("\n"), matches, blocked };
}
