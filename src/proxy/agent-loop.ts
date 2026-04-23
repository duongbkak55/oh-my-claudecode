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
import { join } from "path";
import { homedir } from "os";
import type { CompiledPattern } from "./config.js";
import type { ProxyConfig } from "./config.js";
import type {
  AnthropicContentBlock,
  AnthropicMessage,
  AnthropicRequestBody,
} from "./dlp.js";
import { applyPolicy } from "./dlp.js";
import { validateToolCall } from "./allowlist.js";
import { atomicWriteJsonSync, safeReadJson, ensureDirSync } from "../lib/atomic-write.js";
import type { AuditEvent } from "./audit.js";
import { auditEvent, summarizeMatches } from "./audit.js";

export type ToolFn = (input: Record<string, unknown>) => Promise<string>;
export type ToolRegistry = Map<string, ToolFn>;

export function defaultToolRegistry(): ToolRegistry {
  const reg: ToolRegistry = new Map();
  reg.set("echo", async (input) => {
    const text = typeof input.text === "string" ? input.text : "";
    return text;
  });
  reg.set("read_file", async (input) => {
    const p = typeof input.file_path === "string" ? input.file_path : "";
    if (!p) throw new Error("read_file requires file_path");
    const base = join(homedir(), ".omc", "proxy", "allowed");
    if (!p.startsWith(base + "/") && p !== base) {
      throw new Error(`read_file: '${p}' not under allowed root`);
    }
    return await readFile(p, "utf-8");
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
  return join(process.cwd(), ".omc", "proxy", "hitl");
}

async function waitForHitlDecision(
  id: string,
  timeoutMs: number,
): Promise<"approved" | "denied" | "timeout"> {
  const file = join(hitlDir(), `${id}.json`);
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    const rec = await safeReadJson<HitlRecord>(file);
    if (rec && (rec.status === "approved" || rec.status === "denied")) {
      return rec.status;
    }
    await new Promise((r) => setTimeout(r, 250));
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
}

export async function runAgentLoop(
  request: AnthropicRequestBody,
  deps: AgentLoopDeps,
): Promise<UpstreamResponse> {
  const { config, upstream, tools, patterns, auditDir, reqId } = deps;
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
    lastResponse = await upstream.createMessage(iterReq);
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
        auditEvent(auditDir, evt);
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
        ensureDirSync(hitlDir());
        atomicWriteJsonSync(join(hitlDir(), `${id}.json`), rec);
        auditEvent(auditDir, {
          reqId,
          phase: "hitl",
          meta: { hitlId: id, toolName: name, status: "pending" },
        });
        const decision = await waitForHitlDecision(id, config.hitl.timeoutMs);
        auditEvent(auditDir, {
          reqId,
          phase: "hitl",
          meta: { hitlId: id, toolName: name, status: decision },
        });
        if (decision !== "approved") {
          return {
            role: "assistant",
            content: [
              {
                type: "text",
                text: `Tool call '${name}' ${decision === "denied" ? "denied" : "timed out"} by HITL review`,
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

      // DLP-filter the tool output before it goes back upstream.
      const filtered = applyPolicy(toolOutput, patterns);
      auditEvent(auditDir, {
        reqId,
        phase: "tool",
        dlpMatches: summarizeMatches(filtered.matches),
        blocked: filtered.blocked,
        meta: { toolName: name, isError },
      });

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
