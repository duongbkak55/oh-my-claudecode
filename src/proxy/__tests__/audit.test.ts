import { describe, it, expect, beforeEach } from "vitest";
import { mkdtempSync, readFileSync, readdirSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { auditEvent, auditFilePath, summarizeMatches } from "../audit.js";
import { compilePatterns, type DlpMatch } from "../dlp.js";

function freshDir(): string {
  return mkdtempSync(join(tmpdir(), "omc-proxy-audit-"));
}

describe("audit", () => {
  let dir: string;
  beforeEach(() => {
    dir = freshDir();
  });

  it("writes one JSONL entry per event", () => {
    auditEvent(dir, { reqId: "a", phase: "request" });
    auditEvent(dir, { reqId: "b", phase: "response" });
    const file = auditFilePath(dir);
    const lines = readFileSync(file, "utf-8")
      .split("\n")
      .filter((l) => l.length > 0);
    expect(lines.length).toBe(2);
    const first = JSON.parse(lines[0]!);
    expect(first.reqId).toBe("a");
    expect(first.phase).toBe("request");
    expect(typeof first.ts).toBe("string");
  });

  it("rotates filename by UTC date", () => {
    const today = auditFilePath(dir);
    const pastFile = auditFilePath(dir, new Date("2020-01-15T00:00:00Z"));
    expect(today).not.toBe(pastFile);
    expect(pastFile).toMatch(/2020-01-15\.jsonl$/);
  });

  it("never persists raw sensitive text; only pattern names+counts", () => {
    const secret = "sk-super-secret-deadbeef-AAAA";
    const fakeMatches: DlpMatch[] = [
      {
        patternName: "generic_api_key",
        policy: "block",
        start: 0,
        end: secret.length,
        sample: "sk**********",
      },
    ];
    auditEvent(dir, {
      reqId: "r1",
      phase: "block",
      dlpMatches: summarizeMatches(fakeMatches),
      blocked: true,
    });
    const file = auditFilePath(dir);
    const contents = readFileSync(file, "utf-8");
    expect(contents).not.toContain(secret);
    expect(contents).toContain("generic_api_key");
  });

  it("creates the audit dir if missing", () => {
    const nested = join(dir, "deep", "nested");
    auditEvent(nested, { reqId: "x", phase: "request" });
    const files = readdirSync(nested);
    expect(files.some((f) => f.endsWith(".jsonl"))).toBe(true);
  });

  it("persists writes durably — data reads back after a single write", () => {
    // Smoke test for the fsync-on-writable-fd path.
    auditEvent(dir, { reqId: "durable-1", phase: "request" });
    const file = auditFilePath(dir);
    const content = readFileSync(file, "utf-8");
    const lines = content.split("\n").filter((l) => l.length > 0);
    expect(lines.length).toBe(1);
    const parsed = JSON.parse(lines[0]!);
    expect(parsed.reqId).toBe("durable-1");
  });

  it("DLP-scans event.error when patterns are provided", () => {
    const patterns = compilePatterns([
      {
        name: "email",
        regex: "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}",
        policy: "redact",
      },
    ]);
    auditEvent(
      dir,
      {
        reqId: "scan-1",
        phase: "error",
        error: "upstream said: leaked@corp.local was bad",
      },
      patterns,
    );
    const file = auditFilePath(dir);
    const content = readFileSync(file, "utf-8");
    expect(content).not.toContain("leaked@corp.local");
    expect(content).toContain("[REDACTED:email]");
  });
});
