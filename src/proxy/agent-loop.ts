/**
 * Server-side agent loop: when clients request `metadata.agent_loop: true`,
 * the proxy drives the tool-use cycle internally. Tool outputs are filtered
 * through DLP before being re-injected into the prompt so untrusted tool
 * results cannot exfiltrate secrets back through the model.
 *
 * This PoC ships with two stub tools (echo + read_file). Real MCP client
 * wiring is a TODO — replace toolRegistry entries with MCP client calls.
 */

import { randomUUID } from "crypto";
import { readFile } from "fs/promises";
import * as fs from "fs";
import * as path from "path";
import { homedir } from "os";
import { z } from "zod";
import type { CompiledPattern } from "./config.js";
import type { ProxyConfig } from "./config.js";
import type {
  AnthropicContentBlock,
  AnthropicMessage,
  AnthropicRequestBody,
} from "./dlp.js";
import { applyPolicy } from "./dlp.js";
import { validateToolCall } from "./allowlist.js";
import { atomicWriteJsonSync, safeReadJson } from "../lib/atomic-write.js";
import type { AuditEvent } from "./audit.js";
import { auditEvent, summarizeMatches } from "./audit.js";

/**
 * Thrown when upstream returns a response that doesn't match the expected
 * Anthropic message shape.
 */
export class UpstreamShapeError extends Error {
  readonly issues: unknown;
  constructor(message: string, issues: unknown) {
    super(message);
    this.name = "UpstreamShapeError";
    this.issues = issues;
  }
}

const TextBlockSchema = z.object({
  type: z.literal("text"),
  text: z.string(),
});

const ToolUseBlockSchema = z.object({
  type: z.literal("tool_use"),
  id: z.string(),
  name: z.string(),
  input: z.record(z.unknown()).optional(),
});

const ThinkingBlockSchema = z.object({
  type: z.literal("thinking"),
  thinking: z.string().optional(),
});

export const UpstreamResponseSchema = z.object({
  id: z.string(),
  model: z.string(),
  role: z.literal("assistant"),
  content: z.array(
    z.union([TextBlockSchema, ToolUseBlockSchema, ThinkingBlockSchema]),
  ),
  stop_reason: z.string().nullable().optional(),
  usage: z.record(z.unknown()).optional(),
});

export function parseUpstreamResponse(raw: unknown): UpstreamResponse {
  const parsed = UpstreamResponseSchema.safeParse(raw);
  if (!parsed.success) {
    throw new UpstreamShapeError(
      "upstream response failed schema validation",
      parsed.error.issues,
    );
  }
  return parsed.data as UpstreamResponse;
}

export type ToolFn = (input: Record<string, unknown>) => Promise<string>;
export type ToolRegistry = Map<string, ToolFn>;

export function defaultToolRegistry(): ToolRegistry {
  const reg: ToolRegistry = new Map();
  reg.set("echo", async (input) => {
    const text = typeof input.text === "string" ? input.text : "";
    return text;
  });

  // Compute once; callers can swap homedir for tests but the default
  // registry is single-tenant so caching is fine.
  let baseRealCache: string | null = null;
  const getBaseReal = (): string => {
    if (baseRealCache) return baseRealCache;
    const base = path.join(homedir(), ".omc", "proxy", "allowed");
    try {
      baseRealCache = fs.realpathSync(base);
    } catch {
      baseRealCache = path.resolve(base);
    }
    return baseRealCache;
  };

  reg.set("read_file", async (input) => {
    const p = typeof input.file_path === "string" ? input.file_path : "";
    if (!p) throw new Error("read_file requires file_path");
    const resolved = path.resolve(p);
    // Reject symlinks outright (defense-in-depth).
    let lst: fs.Stats;
    try {
      lst = fs.lstatSync(resolved);
    } catch (err) {
      throw new Error(`read_file: cannot stat '${p}': ${String(err)}`);
    }
    if (lst.isSymbolicLink()) {
      throw new Error(`read_file: symlinks are not permitted: '${p}'`);
    }
    let real: string;
    try {
      real = fs.realpathSync(resolved);
    } catch (err) {
      throw new Error(`read_file: cannot realpath '${p}': ${String(err)}`);
    }
    const baseReal = getBaseReal();
    const boundary = baseReal.endsWith(path.sep)
      ? baseReal
      : `${baseReal}${path.sep}`;
    if (real !== baseReal && !real.startsWith(boundary)) {
      throw new Error(`read_file: '${p}' not under allowed root`);
    }
    return await readFile(real, "utf-8");
  });
  return reg;
}

export interface UpstreamClient {
  createMessage: (body: AnthropicRequestBody) => Promise<UpstreamResponse>;
}

export interface UpstreamResponse {
  id?: string;
  role?: string;
  content: AnthropicContentBlock[];
  stop_reason?: string;
  model?: string;
  usage?: Record<string, unknown>;
}

interface HitlRecord {
  id: string;
  reqId: string;
  toolName: string;
  input: Record<string, unknown>;
  status: "pending" | "approved" | "denied";
  createdAt: string;
  decidedAt?: string;
}

function hitlDir(): string {
  return path.join(process.cwd(), ".omc", "proxy", "hitl");
}

function ensureHitlDirSecure(): string {
  const dir = hitlDir();
  fs.mkdirSync(dir, { mode: 0o700, recursive: true });
  try {
    fs.chmodSync(dir, 0o700);
  } catch {
    // Best-effort on exotic filesystems.
  }
  return dir;
}

/**
 * Verify an HITL decision file: must not be group/world-accessible and must be
 * owned by this process's uid. Returns the parsed record or null if the file
 * is untrusted / missing / malformed.
 */
async function readTrustedHitl(file: string): Promise<HitlRecord | null> {
  let fd: number;
  try {
    fd = fs.openSync(file, "r");
  } catch {
    return null;
  }
  try {
    const st = fs.fstatSync(fd);
    if ((st.mode & 0o077) !== 0) return null;
    const myUid =
      typeof process.getuid === "function" ? process.getuid() : undefined;
    if (myUid !== undefined && st.uid !== myUid) return null;
  } finally {
    fs.closeSync(fd);
  }
  // Re-stat the path to guard against TOCTOU replacement.
  try {
    const st2 = fs.lstatSync(file);
    if ((st2.mode & 0o077) !== 0) return null;
    if (st2.isSymbolicLink()) return null;
  } catch {
    return null;
  }
  const rec = await safeReadJson<HitlRecord>(file);
  return rec;
}

async function waitForHitlDecision(
  id: string,
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<"approved" | "denied" | "timeout" | "aborted"> {
  if (signal?.aborted) return "aborted";
  const file = path.join(hitlDir(), `${id}.json`);
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (signal?.aborted) return "aborted";
    const rec = await readTrustedHitl(file);
    if (rec && (rec.status === "approved" || rec.status === "denied")) {
      return rec.status;
    }
    await new Promise<void>((resolve, reject) => {
      const t = setTimeout(resolve, 250);
      t.unref();
      if (signal) {
        const onAbort = (): void => {
          clearTimeout(t);
          reject(new Error("aborted"));
        };
        signal.addEventListener("abort", onAbort, { once: true });
      }
    }).catch(() => {
      /* aborted; the outer loop will observe signal.aborted */
    });
  }
  return "timeout";
}

export interface AgentLoopDeps {
  config: ProxyConfig;
  upstream: UpstreamClient;
  tools: ToolRegistry;
  patterns: CompiledPattern[];
  auditDir: string;
  reqId: string;
  abortSignal?: AbortSignal;
}

function truncateToolOutput(s: string, maxBytes: number): string {
  const byteLen = Buffer.byteLength(s, "utf-8");
  if (byteLen <= maxBytes) return s;
  // Slice in characters but re-check bytes; overshoot is OK.
  const slice = Buffer.from(s, "utf-8").subarray(0, maxBytes).toString("utf-8");
  const dropped = byteLen - Buffer.byteLength(slice, "utf-8");
  return `${slice}…[truncated ${dropped} bytes]`;
}

export async function runAgentLoop(
  request: AnthropicRequestBody,
  deps: AgentLoopDeps,
): Promise<UpstreamResponse> {
  const { config, upstream, tools, patterns, auditDir, reqId, abortSignal } = deps;
  const maxIterations = config.agentLoop.maxIterations;
  const messages: AnthropicMessage[] = Array.isArray(request.messages)
    ? JSON.parse(JSON.stringify(request.messages))
    : [];

  let lastResponse: UpstreamResponse | null = null;

  for (let iter = 0; iter < maxIterations; iter++) {
    const iterReq: AnthropicRequestBody = {
      ...request,
      messages,
      stream: false,
    };
    const rawResp = await upstream.createMessage(iterReq);
    // Validate shape before we trust it. The upstream client may already
    // return a typed value, but we re-validate here defensively so a future
    // client change can't smuggle through an unvalidated response.
    try {
      lastResponse = parseUpstreamResponse(rawResp);
    } catch (err) {
      if (err instanceof UpstreamShapeError) {
        throw err;
      }
      throw new UpstreamShapeError(String(err), undefined);
    }
    const toolUses = lastResponse.content.filter(
      (b) => b && b.type === "tool_use",
    );
    if (toolUses.length === 0) {
      return lastResponse;
    }

    // record assistant turn
    messages.push({
      role: "assistant",
      content: lastResponse.content,
    });

    const toolResults: AnthropicContentBlock[] = [];
    for (const block of toolUses) {
      const name = typeof block.name === "string" ? block.name : "";
      const input = (block.input as Record<string, unknown>) ?? {};
      const blockId = (block as unknown as { id?: unknown }).id;
      const toolUseId = typeof blockId === "string" ? blockId : randomUUID();

      const check = validateToolCall({ name, input }, config.allowlist);
      if (!check.allowed) {
        const evt: AuditEvent = {
          reqId,
          phase: "block",
          error: check.reason,
          meta: { toolName: name },
        };
        auditEvent(auditDir, evt, patterns);
        return {
          role: "assistant",
          content: [
            {
              type: "text",
              text: `Tool call blocked: ${check.reason ?? "policy violation"}`,
            },
          ],
          stop_reason: "end_turn",
          model: lastResponse.model,
        };
      }

      if (
        config.hitl.enabled &&
        config.hitl.sensitiveTools.includes(name)
      ) {
        const id = randomUUID();
        const rec: HitlRecord = {
          id,
          reqId,
          toolName: name,
          input,
          status: "pending",
          createdAt: new Date().toISOString(),
        };
        ensureHitlDirSecure();
        atomicWriteJsonSync(path.join(hitlDir(), `${id}.json`), rec);
        try {
          fs.chmodSync(path.join(hitlDir(), `${id}.json`), 0o600);
        } catch {
          // best effort
        }
        auditEvent(auditDir, {
          reqId,
          phase: "hitl",
          meta: { hitlId: id, toolName: name, status: "pending" },
        });
        const decision = await waitForHitlDecision(
          id,
          config.hitl.timeoutMs,
          abortSignal,
        );
        auditEvent(auditDir, {
          reqId,
          phase: "hitl",
          meta: { hitlId: id, toolName: name, status: decision },
        });
        if (decision !== "approved") {
          const reasonLabel =
            decision === "denied"
              ? "denied"
              : decision === "aborted"
                ? "aborted"
                : "timed out";
          return {
            role: "assistant",
            content: [
              {
                type: "text",
                text: `Tool call '${name}' ${reasonLabel} by HITL review`,
              },
            ],
            stop_reason: "end_turn",
            model: lastResponse.model,
          };
        }
      }

      const fn = tools.get(name);
      let toolOutput: string;
      let isError = false;
      if (!fn) {
        toolOutput = `Tool '${name}' is not registered`;
        isError = true;
      } else {
        try {
          toolOutput = await fn(input);
        } catch (err) {
          toolOutput = `Tool '${name}' error: ${String(err)}`;
          isError = true;
        }
      }

      // Cap tool output size so a runaway tool can't blow up memory or
      // upstream context window.
      const maxToolBytes = config.agentLoop.maxToolOutputBytes ?? 100_000;
      toolOutput = truncateToolOutput(toolOutput, maxToolBytes);

      // DLP-filter the tool output before it goes back upstream.
      const filtered = applyPolicy(toolOutput, patterns);
      auditEvent(
        auditDir,
        {
          reqId,
          phase: "tool",
          dlpMatches: summarizeMatches(filtered.matches),
          blocked: filtered.blocked,
          meta: { toolName: name, isError },
        },
        patterns,
      );

      const safeOutput = filtered.blocked
        ? `[BLOCKED:dlp] tool output suppressed by policy`
        : filtered.output;

      toolResults.push({
        type: "tool_result",
        tool_use_id: toolUseId,
        content: safeOutput,
        is_error: isError || filtered.blocked,
      } as AnthropicContentBlock);
    }

    messages.push({
      role: "user",
      content: toolResults,
    });
  }

  // Max iterations reached
  return (
    lastResponse ?? {
      role: "assistant",
      content: [
        { type: "text", text: "Agent loop exhausted without final response." },
      ],
      stop_reason: "end_turn",
    }
  );
}
