/**
 * Audit log: append-only JSONL, rotated per day.
 *
 * NOTE: we intentionally use fs.appendFileSync + fsyncSync here rather than the
 * atomic-rename pattern exposed by src/lib/atomic-write.ts. Atomic rename
 * replaces the target file, which would truncate previous audit entries.
 * Append-with-fsync preserves history while still flushing to disk for each
 * event.
 *
 * Never log raw sensitive text. Only pattern names + counts are persisted.
 */

import { openSync, writeSync, fsyncSync, closeSync } from "fs";
import { join } from "path";
import { ensureDirSync } from "../lib/atomic-write.js";
import type { DlpMatch } from "./dlp.js";
import type { CompiledPattern } from "./config.js";
import { applyPolicy } from "./dlp.js";

export interface DlpMatchSummary {
  name: string;
  policy: "block" | "redact";
  count: number;
}

export type AuditPhase =
  | "request"
  | "response"
  | "tool"
  | "block"
  | "hitl"
  | "error";

export interface AuditEvent {
  ts?: string;
  reqId: string;
  clientIp?: string;
  phase: AuditPhase;
  model?: string;
  dlpMatches?: DlpMatchSummary[];
  blocked?: boolean;
  bytesIn?: number;
  bytesOut?: number;
  latencyMs?: number;
  error?: string;
  // Extra, caller-supplied fields. MUST NOT contain raw sensitive data.
  meta?: Record<string, string | number | boolean>;
}

export function summarizeMatches(matches: DlpMatch[]): DlpMatchSummary[] {
  const counts = new Map<string, { policy: "block" | "redact"; count: number }>();
  for (const m of matches) {
    const prev = counts.get(m.patternName);
    if (prev) prev.count += 1;
    else counts.set(m.patternName, { policy: m.policy, count: 1 });
  }
  return Array.from(counts.entries()).map(([name, v]) => ({
    name,
    policy: v.policy,
    count: v.count,
  }));
}

function currentDayFile(dir: string, now: Date = new Date()): string {
  const y = now.getUTCFullYear();
  const m = String(now.getUTCMonth() + 1).padStart(2, "0");
  const d = String(now.getUTCDate()).padStart(2, "0");
  return join(dir, `${y}-${m}-${d}.jsonl`);
}

export function auditEvent(
  dir: string,
  event: AuditEvent,
  patterns?: CompiledPattern[],
): void {
  ensureDirSync(dir);
  const withTs: AuditEvent = {
    ...event,
    ts: event.ts ?? new Date().toISOString(),
  };
  // Belt-and-braces: if the caller passed compiled DLP patterns and the
  // event has an `error` string, scan that string so a raw upstream/stack
  // snippet can't accidentally persist a secret to audit.
  if (patterns && patterns.length > 0 && typeof withTs.error === "string") {
    const r = applyPolicy(withTs.error, patterns);
    withTs.error = r.blocked ? "[BLOCKED:dlp]" : r.output;
  }
  const file = currentDayFile(dir);
  const line = JSON.stringify(withTs) + "\n";
  // Open append-fd once, write, fsync, close — durability on the writable fd.
  const fd = openSync(file, "a", 0o600);
  try {
    writeSync(fd, line);
    try {
      fsyncSync(fd);
    } catch {
      // Some filesystems don't support fsync; best-effort only.
    }
  } finally {
    closeSync(fd);
  }
}

export function auditFilePath(dir: string, date?: Date): string {
  return currentDayFile(dir, date);
}
