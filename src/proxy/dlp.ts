/**
 * DLP pipeline — scans text for sensitive patterns and applies block/redact
 * policy. Also provides helpers for Anthropic-shaped request bodies and SSE
 * streaming chunks.
 */

import safeRegexDefault from "safe-regex";
import type { CompiledPattern } from "./config.js";
import type { TokenVault } from "./vault.js";
import { TOKEN_REGEX } from "./vault.js";
import type { Dictionary, DictionaryMatch } from "./dictionary.js";
import type { SqlLane } from "./sql-lane.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const safeRegex: (re: RegExp | string) => boolean = safeRegexDefault as any;

export interface DlpMatch {
  patternName: string;
  policy: "block" | "redact" | "tokenize";
  start: number;
  end: number;
  sample: string;
}

export interface DlpRawPattern {
  name: string;
  regex: string;
  policy: "block" | "redact" | "tokenize";
  replacement?: string;
}

export interface VaultContext {
  convId: string;
  vault: TokenVault;
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

export interface ApplyPolicyOptions {
  vault?: VaultContext;
  dictionary?: Dictionary;
  sqlLane?: SqlLane;
}

interface ActionableMatch {
  start: number;
  end: number;
  policy: "redact" | "tokenize";
  patternName: string;
  classifier: string;
  original: string;
}

export function applyPolicy(
  text: string,
  patterns: CompiledPattern[],
  opts: ApplyPolicyOptions = {},
): ApplyPolicyResult {
  // Pass 0: SQL lane (structural rewrite, may change text length). Runs first
  // so regex/dict offsets remain valid on the already-SQL-masked output.
  let workText = text;
  const sqlMatches: DlpMatch[] = [];
  if (opts.sqlLane && opts.vault) {
    const r = opts.sqlLane.apply(text, opts.vault);
    workText = r.output;
    for (const m of r.matches) sqlMatches.push(m);
  }
  const regexMatches = scan(workText, patterns);
  const dictMatches: DictionaryMatch[] = opts.dictionary
    ? opts.dictionary.scan(workText)
    : [];
  const hasBlock =
    regexMatches.some((m) => m.policy === "block") ||
    dictMatches.some((m) => m.policy === "block");
  // Lift dictionary hits into DlpMatch[] for reporting uniformly. SQL-lane
  // matches are pre-populated (structural rewrites already applied upstream).
  const allMatches: DlpMatch[] = [...sqlMatches, ...regexMatches];
  for (const d of dictMatches) {
    allMatches.push({
      patternName: `dict:${d.classifier}`,
      policy: d.policy,
      start: d.start,
      end: d.end,
      sample: maskSample(workText.slice(d.start, d.end)),
    });
  }
  if (hasBlock) {
    return { output: workText, matches: allMatches, blocked: true };
  }
  // Build a merged, non-overlapping action list preferring earlier start;
  // ties broken by longest match so a tokenized dict term beats a partial
  // regex hit at the same start.
  const actions: ActionableMatch[] = [];
  for (const m of regexMatches) {
    if (m.policy === "block") continue;
    actions.push({
      start: m.start,
      end: m.end,
      policy: m.policy,
      patternName: m.patternName,
      classifier: m.patternName,
      original: workText.slice(m.start, m.end),
    });
  }
  for (const d of dictMatches) {
    if (d.policy === "block") continue;
    actions.push({
      start: d.start,
      end: d.end,
      policy: d.policy,
      patternName: `dict:${d.classifier}`,
      classifier: d.classifier,
      original: workText.slice(d.start, d.end),
    });
  }
  if (actions.length === 0) {
    return { output: workText, matches: allMatches, blocked: false };
  }
  actions.sort((a, b) => {
    if (a.start !== b.start) return a.start - b.start;
    return b.end - a.end;
  });
  let out = "";
  let cursor = 0;
  for (const m of actions) {
    if (m.start < cursor) continue;
    out += workText.slice(cursor, m.start);
    if (m.policy === "tokenize" && opts.vault) {
      const token = opts.vault.vault.issue(
        opts.vault.convId,
        m.classifier,
        m.original,
      );
      out += token;
    } else {
      const replacement = findReplacement(patterns, m.patternName);
      out += replacement ?? `[REDACTED:${m.patternName}]`;
    }
    cursor = m.end;
  }
  out += workText.slice(cursor);
  return { output: out, matches: allMatches, blocked: false };
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
  opts: ApplyPolicyOptions = {},
): { text: string; blocked: boolean } {
  const r = applyPolicy(s, patterns, opts);
  for (const m of r.matches) {
    matches.push(m);
    if (m.policy === "block") reasons.add(m.patternName);
  }
  return { text: r.output, blocked: r.blocked };
}

// Keys whose string values are *structural* — i.e. not user/model content and
// therefore must NOT be scanned for secrets (scanning them would produce
// false positives like a tool named "sk-test-tool" tripping `generic_api_key`).
const STRUCTURAL_KEYS = new Set<string>([
  "type",
  "id",
  "role",
  "index",
  "stop_reason",
  "model",
  "name",
  "tool_use_id",
]);

/**
 * Recursively walks a value and redacts every string it encounters, EXCEPT
 * strings whose parent key is in STRUCTURAL_KEYS. Mutates objects/arrays
 * in-place and returns whether any `block` policy fired.
 *
 * NOTE: caller is responsible for deep-cloning before passing in if they don't
 * want the original mutated.
 */
export function walkAndRedact(
  value: unknown,
  patterns: CompiledPattern[],
  matches: DlpMatch[],
  reasons: Set<string>,
  opts: ApplyPolicyOptions = {},
): { value: unknown; blocked: boolean } {
  let blocked = false;
  if (value === null || value === undefined) {
    return { value, blocked };
  }
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      const r = walkAndRedact(value[i], patterns, matches, reasons, opts);
      value[i] = r.value;
      blocked = blocked || r.blocked;
    }
    return { value, blocked };
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    for (const [k, v] of Object.entries(obj)) {
      if (typeof v === "string") {
        if (STRUCTURAL_KEYS.has(k)) continue;
        const r = redactString(v, patterns, matches, reasons, opts);
        obj[k] = r.text;
        blocked = blocked || r.blocked;
      } else if (v !== null && typeof v === "object") {
        const r = walkAndRedact(v, patterns, matches, reasons, opts);
        obj[k] = r.value;
        blocked = blocked || r.blocked;
      }
    }
    return { value: obj, blocked };
  }
  return { value, blocked };
}

const DLP_INSTRUCTION =
  "[OMC-DLP]: Preserve identifier tokens of the form EMAIL_NN, PHONE_NN, " +
  "PERSON_NN, PKG_NN, CN_NN, CUSTOMER_NN, HOST_NN, TICKET_NN verbatim. " +
  "Do not rename, paraphrase, or correct typos in these tokens.";

function injectDlpInstruction(body: AnthropicRequestBody): void {
  if (typeof body.system === "string") {
    if (body.system.includes("[OMC-DLP]")) return;
    body.system = body.system.length > 0
      ? `${DLP_INSTRUCTION}\n\n${body.system}`
      : DLP_INSTRUCTION;
    return;
  }
  if (Array.isArray(body.system)) {
    const already = body.system.some(
      (b) => b && typeof b.text === "string" && b.text.includes("[OMC-DLP]"),
    );
    if (already) return;
    body.system.unshift({ type: "text", text: DLP_INSTRUCTION });
    return;
  }
  body.system = DLP_INSTRUCTION;
}

export function redactAnthropicRequest(
  body: AnthropicRequestBody,
  patterns: CompiledPattern[],
  opts: ApplyPolicyOptions = {},
): RedactRequestResult {
  const matches: DlpMatch[] = [];
  const reasons = new Set<string>();
  let blocked = false;

  // deep clone so we don't mutate the caller's object
  const clone = JSON.parse(JSON.stringify(body)) as AnthropicRequestBody;

  // Determine whether any tokenize policy could fire. If yes, and a vault is
  // supplied, pre-inject the DLP instruction into `system` BEFORE walking so
  // it survives the scan and the model sees it.
  const mightTokenize =
    !!opts.vault &&
    (patterns.some((p) => p.policy === "tokenize") ||
      // dictionary entries with tokenize policy — cheap check: always inject
      // when a dictionary is present; injection is idempotent.
      !!opts.dictionary);
  if (mightTokenize) {
    injectDlpInstruction(clone);
  }

  if (typeof clone.system === "string") {
    const r = redactString(clone.system, patterns, matches, reasons, opts);
    clone.system = r.text;
    blocked = blocked || r.blocked;
  } else if (Array.isArray(clone.system)) {
    for (const block of clone.system) {
      if (block && typeof block.text === "string") {
        const r = redactString(block.text, patterns, matches, reasons, opts);
        block.text = r.text;
        blocked = blocked || r.blocked;
      }
    }
  }

  if (Array.isArray(clone.messages)) {
    for (const msg of clone.messages) {
      if (typeof msg.content === "string") {
        const r = redactString(msg.content, patterns, matches, reasons, opts);
        msg.content = r.text;
        blocked = blocked || r.blocked;
      } else if (Array.isArray(msg.content)) {
        for (const block of msg.content) {
          if (!block || typeof block !== "object") continue;
          // top-level text on a block
          if (typeof block.text === "string") {
            const r = redactString(block.text, patterns, matches, reasons, opts);
            block.text = r.text;
            blocked = blocked || r.blocked;
          }
          // tool_result (and similar) can have content: string | array
          const innerContent = (block as { content?: unknown }).content;
          if (typeof innerContent === "string") {
            const r = redactString(innerContent, patterns, matches, reasons, opts);
            (block as { content?: unknown }).content = r.text;
            blocked = blocked || r.blocked;
          } else if (Array.isArray(innerContent)) {
            const wr = walkAndRedact(innerContent, patterns, matches, reasons, opts);
            (block as { content?: unknown }).content = wr.value;
            blocked = blocked || wr.blocked;
          }
        }
      }
    }
  }

  if (Array.isArray(clone.tools)) {
    for (const tool of clone.tools) {
      if (!tool || typeof tool !== "object") continue;
      const t = tool as Record<string, unknown>;
      if (typeof t.description === "string") {
        const r = redactString(t.description, patterns, matches, reasons, opts);
        t.description = r.text;
        blocked = blocked || r.blocked;
      }
      const schema = t.input_schema;
      if (schema && typeof schema === "object") {
        const wr = walkAndRedact(schema, patterns, matches, reasons, opts);
        t.input_schema = wr.value;
        blocked = blocked || wr.blocked;
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

/**
 * Walk a response-shaped JSON value and replace all occurrences of vault tokens
 * with the original secret. Mutates objects/arrays in-place. Unknown tokens
 * (not in the vault for this convId) pass through unchanged.
 */
export function detokenize(
  text: string,
  convId: string,
  vault: TokenVault,
): string {
  if (!text) return text;
  TOKEN_REGEX.lastIndex = 0;
  return text.replace(TOKEN_REGEX, (tok) => {
    const v = vault.lookup(convId, tok);
    return v ?? tok;
  });
}

export function detokenizeValue(
  value: unknown,
  convId: string,
  vault: TokenVault,
): unknown {
  if (value === null || value === undefined) return value;
  if (typeof value === "string") return detokenize(value, convId, vault);
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      value[i] = detokenizeValue(value[i], convId, vault);
    }
    return value;
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    for (const [k, v] of Object.entries(obj)) {
      if (typeof v === "string") {
        obj[k] = detokenize(v, convId, vault);
      } else if (v !== null && typeof v === "object") {
        obj[k] = detokenizeValue(v, convId, vault);
      }
    }
    return obj;
  }
  return value;
}

// --- SSE rolling redactor --------------------------------------------------

/**
 * Stateful SSE redactor that accumulates per-content-block text across frames
 * so secrets split across chunk boundaries (e.g. "sk-" | "ant-" | "abc...") can
 * still be detected. Emits the "safe prefix" of each buffer (everything except
 * the last HOLD_BACK bytes, which might be the start of a pattern that will
 * complete on the next chunk), holding the tail for the next scan.
 *
 * On `content_block_stop` the tail is flushed through a final scan.
 * On `message_stop` or explicit block hit, all buffers are cleared.
 */
const HOLD_BACK = 512;

interface BlockBuffer {
  buffer: string;
  type: "text" | "thinking" | "partial_json";
  emittedLen: number;
}

export interface SseEmitResult {
  emit: string;
  blocked: boolean;
  blockedPatterns: string[];
  matches: DlpMatch[];
}

export class SseRedactor {
  private readonly patterns: CompiledPattern[];
  private readonly opts: ApplyPolicyOptions;
  private readonly blocks: Map<number, BlockBuffer> = new Map();
  private carry: string = "";
  private streamBlocked = false;

  constructor(patterns: CompiledPattern[], opts: ApplyPolicyOptions = {}) {
    this.patterns = patterns;
    this.opts = opts;
  }

  get blocked(): boolean {
    return this.streamBlocked;
  }

  /**
   * Feed one raw chunk of bytes-as-string from the upstream stream. Returns
   * the safe chunk to write downstream, plus any blocked state.
   */
  push(chunk: string): SseEmitResult {
    if (this.streamBlocked) {
      return { emit: "", blocked: true, blockedPatterns: [], matches: [] };
    }
    this.carry += chunk;
    const out: string[] = [];
    const matches: DlpMatch[] = [];
    const blockedPatterns: string[] = [];
    let idx: number;
    while ((idx = this.carry.indexOf("\n\n")) !== -1) {
      const rawEvent = this.carry.slice(0, idx);
      this.carry = this.carry.slice(idx + 2);
      const processed = this.processEvent(rawEvent);
      for (const m of processed.matches) matches.push(m);
      for (const p of processed.blockedPatterns) blockedPatterns.push(p);
      if (processed.blocked) {
        this.streamBlocked = true;
        out.push(processed.emit);
        // Append the SSE error frame
        out.push(
          `event: error\ndata: ${JSON.stringify({
            type: "dlp_blocked",
            patterns: Array.from(new Set(blockedPatterns)),
          })}\n\n`,
        );
        return {
          emit: out.join(""),
          blocked: true,
          blockedPatterns: Array.from(new Set(blockedPatterns)),
          matches,
        };
      }
      out.push(processed.emit);
    }
    return {
      emit: out.join(""),
      blocked: false,
      blockedPatterns,
      matches,
    };
  }

  /**
   * Flush any trailing carry + per-block buffer tails (called when upstream is
   * done). Emits one synthesized content_block_delta per block that still has
   * unemitted text, so the client sees the full (redacted) content.
   */
  flush(): SseEmitResult {
    if (this.streamBlocked) {
      return { emit: "", blocked: true, blockedPatterns: [], matches: [] };
    }
    const matches: DlpMatch[] = [];
    const blockedPatterns: string[] = [];
    let emit = "";
    if (this.carry.length > 0) {
      const rawEvent = this.carry;
      this.carry = "";
      const processed = this.processEvent(rawEvent);
      for (const m of processed.matches) matches.push(m);
      for (const p of processed.blockedPatterns) blockedPatterns.push(p);
      emit += processed.emit;
      if (processed.blocked) {
        this.streamBlocked = true;
        const errFrame = `event: error\ndata: ${JSON.stringify({
          type: "dlp_blocked",
          patterns: Array.from(new Set(blockedPatterns)),
        })}\n\n`;
        return {
          emit: emit + errFrame,
          blocked: true,
          blockedPatterns,
          matches,
        };
      }
    }
    // Drain per-block buffer tails by synthesizing content_block_delta frames.
    for (const [index, buf] of this.blocks) {
      if (buf.emittedLen >= buf.buffer.length) continue;
      const full = buf.buffer;
      const r = applyPolicy(full, this.patterns, this.opts);
      for (const m of r.matches) matches.push(m);
      if (r.blocked) {
        this.streamBlocked = true;
        for (const m of r.matches.filter((x) => x.policy === "block"))
          blockedPatterns.push(m.patternName);
        const errFrame = `event: error\ndata: ${JSON.stringify({
          type: "dlp_blocked",
          patterns: Array.from(new Set(blockedPatterns)),
        })}\n\n`;
        return {
          emit: emit + errFrame,
          blocked: true,
          blockedPatterns,
          matches,
        };
      }
      // Emit the tail as a final delta frame.
      const tailScan = applyPolicy(
        full.slice(buf.emittedLen),
        this.patterns,
        this.opts,
      );
      const deltaType =
        buf.type === "thinking"
          ? "thinking_delta"
          : buf.type === "partial_json"
            ? "input_json_delta"
            : "text_delta";
      const deltaField =
        buf.type === "thinking"
          ? "thinking"
          : buf.type === "partial_json"
            ? "partial_json"
            : "text";
      const frame = {
        type: "content_block_delta",
        index,
        delta: { type: deltaType, [deltaField]: tailScan.output },
      };
      emit += `data: ${JSON.stringify(frame)}\n\n`;
      buf.emittedLen = full.length;
    }
    this.blocks.clear();
    return { emit, blocked: false, blockedPatterns, matches };
  }

  private processEvent(rawEvent: string): SseEmitResult {
    // An event block may contain multiple `data:` lines. We parse each and
    // transform as appropriate.
    const lines = rawEvent.split(/\r?\n/);
    const outLines: string[] = [];
    const matches: DlpMatch[] = [];
    const blockedPatterns: string[] = [];
    let blocked = false;
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
      let parsed: {
        type?: string;
        index?: number;
        content_block?: { type?: string; text?: string };
        delta?: {
          type?: string;
          text?: string;
          thinking?: string;
          partial_json?: string;
        };
      };
      try {
        parsed = JSON.parse(payload) as typeof parsed;
      } catch {
        outLines.push(line);
        continue;
      }

      const type = parsed.type;
      if (type === "message_stop") {
        this.blocks.clear();
        outLines.push(line);
        continue;
      }

      if (type === "content_block_start" && typeof parsed.index === "number") {
        const cb = parsed.content_block ?? {};
        const btype: "text" | "thinking" | "partial_json" =
          cb.type === "thinking"
            ? "thinking"
            : cb.type === "tool_use" || cb.type === "input_json_delta"
              ? "partial_json"
              : "text";
        const initial = typeof cb.text === "string" ? cb.text : "";
        this.blocks.set(parsed.index, {
          buffer: initial,
          type: btype,
          emittedLen: 0,
        });
        // Emit a safe-prefix variant if the initial text has overlap with a
        // pattern boundary. Usually initial is empty.
        const buf = this.blocks.get(parsed.index)!;
        const safeEnd = Math.max(0, buf.buffer.length - HOLD_BACK);
        const safePrefix = buf.buffer.slice(buf.emittedLen, safeEnd);
        if (safePrefix.length > 0) {
          const r = applyPolicy(safePrefix, this.patterns, this.opts);
          for (const m of r.matches) matches.push(m);
          if (r.blocked) {
            for (const m of r.matches.filter((x) => x.policy === "block"))
              blockedPatterns.push(m.patternName);
            blocked = true;
            // Drop content
            if (cb.text !== undefined) cb.text = "[BLOCKED:dlp]";
            outLines.push(`data: ${JSON.stringify(parsed)}`);
            buf.emittedLen = buf.buffer.length;
            continue;
          }
          if (cb.text !== undefined) cb.text = r.output;
          buf.emittedLen = safeEnd;
          outLines.push(`data: ${JSON.stringify(parsed)}`);
        } else {
          // No safe prefix yet — drop any initial text from the wire payload,
          // it will be emitted from the buffer later.
          if (cb.text !== undefined) cb.text = "";
          outLines.push(`data: ${JSON.stringify(parsed)}`);
        }
        continue;
      }

      if (type === "content_block_delta" && typeof parsed.index === "number") {
        const delta = parsed.delta ?? {};
        const field: "text" | "thinking" | "partial_json" | null =
          typeof delta.text === "string"
            ? "text"
            : typeof delta.thinking === "string"
              ? "thinking"
              : typeof delta.partial_json === "string"
                ? "partial_json"
                : null;
        if (field === null) {
          outLines.push(line);
          continue;
        }
        let buf = this.blocks.get(parsed.index);
        if (!buf) {
          buf = {
            buffer: "",
            type: field,
            emittedLen: 0,
          };
          this.blocks.set(parsed.index, buf);
        }
        const incoming = (delta[field] as string) ?? "";
        buf.buffer += incoming;
        const safeEnd = Math.max(0, buf.buffer.length - HOLD_BACK);
        const unscanned = buf.buffer.slice(buf.emittedLen);
        const unscannedSafeEnd = Math.max(0, safeEnd - buf.emittedLen);
        if (unscannedSafeEnd <= 0) {
          // Nothing safe to emit yet — send a delta with empty text so frame
          // count stays the same (optional; we just drop the delta).
          // Drop: keep index, but emit empty delta text to preserve cadence.
          (delta as Record<string, string>)[field] = "";
          outLines.push(`data: ${JSON.stringify(parsed)}`);
          continue;
        }
        const safeSlice = unscanned.slice(0, unscannedSafeEnd);
        // Now scan the CUMULATIVE not-yet-emitted safe slice in context of
        // buffer (scan on the whole buffer up to safeEnd, then take the
        // incremental output beyond emittedLen).
        const fullScanInput = buf.buffer.slice(0, safeEnd);
        const r = applyPolicy(fullScanInput, this.patterns, this.opts);
        for (const m of r.matches) matches.push(m);
        if (r.blocked) {
          for (const m of r.matches.filter((x) => x.policy === "block"))
            blockedPatterns.push(m.patternName);
          blocked = true;
          (delta as Record<string, string>)[field] = "[BLOCKED:dlp]";
          outLines.push(`data: ${JSON.stringify(parsed)}`);
          buf.emittedLen = buf.buffer.length;
          continue;
        }
        // Take the piece of r.output corresponding to the new slice.
        // Since redaction may have changed lengths earlier, we can't use raw
        // offsets. Simplest correct behavior: emit NOTHING until we're in the
        // flush path, OR emit the processed incremental output — for
        // non-blocked content, re-redact just the new delta (which is the
        // safe slice). That's a local scan; secrets only trigger if the
        // whole accumulator was blocked above, which we already handled.
        const localScan = applyPolicy(safeSlice, this.patterns, this.opts);
        (delta as Record<string, string>)[field] = localScan.output;
        buf.emittedLen += safeSlice.length;
        outLines.push(`data: ${JSON.stringify(parsed)}`);
        continue;
      }

      if (type === "content_block_stop" && typeof parsed.index === "number") {
        const buf = this.blocks.get(parsed.index);
        if (buf && buf.emittedLen < buf.buffer.length) {
          const tail = buf.buffer.slice(buf.emittedLen);
          // Final scan on the FULL buffer catches secrets that span the tail.
          const r = applyPolicy(buf.buffer, this.patterns, this.opts);
          for (const m of r.matches) matches.push(m);
          if (r.blocked) {
            for (const m of r.matches.filter((x) => x.policy === "block"))
              blockedPatterns.push(m.patternName);
            blocked = true;
            // Drop tail — DO NOT emit any further content for this block.
            this.blocks.delete(parsed.index);
            outLines.push(line);
            continue;
          }
          // Emit the tail as a final content_block_delta before the stop.
          // We redact locally (safe because full scan didn't block).
          const tailScan = applyPolicy(tail, this.patterns, this.opts);
          const deltaType =
            buf.type === "thinking"
              ? "thinking_delta"
              : buf.type === "partial_json"
                ? "input_json_delta"
                : "text_delta";
          const deltaField =
            buf.type === "thinking"
              ? "thinking"
              : buf.type === "partial_json"
                ? "partial_json"
                : "text";
          const flushFrame = {
            type: "content_block_delta",
            index: parsed.index,
            delta: { type: deltaType, [deltaField]: tailScan.output },
          };
          outLines.push(`data: ${JSON.stringify(flushFrame)}`);
          outLines.push("");
        }
        this.blocks.delete(parsed.index);
        outLines.push(line);
        continue;
      }

      // Other events (message_start, ping, etc.) pass through unchanged.
      outLines.push(line);
    }
    return {
      emit: outLines.join("\n") + "\n\n",
      blocked,
      blockedPatterns,
      matches,
    };
  }
}

// --- SSE streaming chunk ---------------------------------------------------

/**
 * Redact a single SSE chunk (may contain multiple "event:" / "data:" lines).
 * Applies to `delta.text` on content_block_delta events. Anything that fails
 * to parse is forwarded unchanged to avoid breaking the stream.
 */
/**
 * Inverse of SseRedactor. Buffers per-content-block text until HOLD_BACK bytes
 * have been seen, then scans for vault tokens and replaces them with their
 * original value. Handles tokens split across SSE delta frames.
 *
 * Unknown tokens (not in the vault) pass through unchanged — they may be
 * content the model emitted that just happens to look like our token shape.
 */
interface DetokBuffer {
  buffer: string;
  type: "text" | "thinking" | "partial_json";
  emittedLen: number;
}

export interface SseDetokenizeResult {
  emit: string;
}

export class SseDetokenizer {
  private readonly convId: string;
  private readonly vault: TokenVault;
  private readonly blocks: Map<number, DetokBuffer> = new Map();
  private carry: string = "";

  constructor(convId: string, vault: TokenVault) {
    this.convId = convId;
    this.vault = vault;
  }

  push(chunk: string): SseDetokenizeResult {
    this.carry += chunk;
    const out: string[] = [];
    let idx: number;
    while ((idx = this.carry.indexOf("\n\n")) !== -1) {
      const rawEvent = this.carry.slice(0, idx);
      this.carry = this.carry.slice(idx + 2);
      out.push(this.processEvent(rawEvent));
    }
    return { emit: out.join("") };
  }

  flush(): SseDetokenizeResult {
    const out: string[] = [];
    if (this.carry.length > 0) {
      const rawEvent = this.carry;
      this.carry = "";
      out.push(this.processEvent(rawEvent));
    }
    // Drain tails.
    for (const [index, buf] of this.blocks) {
      if (buf.emittedLen >= buf.buffer.length) continue;
      const tail = buf.buffer.slice(buf.emittedLen);
      const detoked = detokenize(tail, this.convId, this.vault);
      const deltaType =
        buf.type === "thinking"
          ? "thinking_delta"
          : buf.type === "partial_json"
            ? "input_json_delta"
            : "text_delta";
      const deltaField =
        buf.type === "thinking"
          ? "thinking"
          : buf.type === "partial_json"
            ? "partial_json"
            : "text";
      const frame = {
        type: "content_block_delta",
        index,
        delta: { type: deltaType, [deltaField]: detoked },
      };
      out.push(`data: ${JSON.stringify(frame)}\n\n`);
      buf.emittedLen = buf.buffer.length;
    }
    this.blocks.clear();
    return { emit: out.join("") };
  }

  private processEvent(rawEvent: string): string {
    const lines = rawEvent.split(/\r?\n/);
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
      let parsed: {
        type?: string;
        index?: number;
        content_block?: { type?: string; text?: string };
        delta?: {
          type?: string;
          text?: string;
          thinking?: string;
          partial_json?: string;
        };
      };
      try {
        parsed = JSON.parse(payload) as typeof parsed;
      } catch {
        outLines.push(line);
        continue;
      }
      const type = parsed.type;
      if (type === "content_block_start" && typeof parsed.index === "number") {
        const cb = parsed.content_block ?? {};
        const btype: "text" | "thinking" | "partial_json" =
          cb.type === "thinking"
            ? "thinking"
            : cb.type === "tool_use" || cb.type === "input_json_delta"
              ? "partial_json"
              : "text";
        const initial = typeof cb.text === "string" ? cb.text : "";
        this.blocks.set(parsed.index, {
          buffer: initial,
          type: btype,
          emittedLen: 0,
        });
        if (cb.text !== undefined) cb.text = "";
        outLines.push(`data: ${JSON.stringify(parsed)}`);
        continue;
      }
      if (type === "content_block_delta" && typeof parsed.index === "number") {
        const delta = parsed.delta ?? {};
        const field: "text" | "thinking" | "partial_json" | null =
          typeof delta.text === "string"
            ? "text"
            : typeof delta.thinking === "string"
              ? "thinking"
              : typeof delta.partial_json === "string"
                ? "partial_json"
                : null;
        if (field === null) {
          outLines.push(line);
          continue;
        }
        let buf = this.blocks.get(parsed.index);
        if (!buf) {
          buf = { buffer: "", type: field, emittedLen: 0 };
          this.blocks.set(parsed.index, buf);
        }
        const incoming = (delta[field] as string) ?? "";
        buf.buffer += incoming;
        const safeEnd = Math.max(0, buf.buffer.length - HOLD_BACK);
        const unscannedSafeEnd = Math.max(0, safeEnd - buf.emittedLen);
        if (unscannedSafeEnd <= 0) {
          (delta as Record<string, string>)[field] = "";
          outLines.push(`data: ${JSON.stringify(parsed)}`);
          continue;
        }
        const safeSlice = buf.buffer.slice(
          buf.emittedLen,
          buf.emittedLen + unscannedSafeEnd,
        );
        const detoked = detokenize(safeSlice, this.convId, this.vault);
        (delta as Record<string, string>)[field] = detoked;
        buf.emittedLen += safeSlice.length;
        outLines.push(`data: ${JSON.stringify(parsed)}`);
        continue;
      }
      if (type === "content_block_stop" && typeof parsed.index === "number") {
        const buf = this.blocks.get(parsed.index);
        if (buf && buf.emittedLen < buf.buffer.length) {
          const tail = buf.buffer.slice(buf.emittedLen);
          const detoked = detokenize(tail, this.convId, this.vault);
          const deltaType =
            buf.type === "thinking"
              ? "thinking_delta"
              : buf.type === "partial_json"
                ? "input_json_delta"
                : "text_delta";
          const deltaField =
            buf.type === "thinking"
              ? "thinking"
              : buf.type === "partial_json"
                ? "partial_json"
                : "text";
          const flushFrame = {
            type: "content_block_delta",
            index: parsed.index,
            delta: { type: deltaType, [deltaField]: detoked },
          };
          outLines.push(`data: ${JSON.stringify(flushFrame)}`);
          outLines.push("");
          buf.emittedLen = buf.buffer.length;
        }
        this.blocks.delete(parsed.index);
        outLines.push(line);
        continue;
      }
      if (type === "message_stop") {
        this.blocks.clear();
        outLines.push(line);
        continue;
      }
      outLines.push(line);
    }
    return outLines.join("\n") + "\n\n";
  }
}

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
