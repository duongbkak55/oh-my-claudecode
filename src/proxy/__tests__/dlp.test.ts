import { describe, it, expect } from "vitest";
import {
  applyPolicy,
  compilePatterns,
  redactAnthropicRequest,
  redactStreamingChunk,
  scan,
  type DlpRawPattern,
} from "../dlp.js";

const defaults: DlpRawPattern[] = [
  {
    name: "email",
    regex: "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}",
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
  { name: "cccd_vn", regex: "\\b\\d{12}\\b", policy: "redact" },
];

describe("dlp.scan/applyPolicy", () => {
  it("detects email and redacts it", () => {
    const patterns = compilePatterns(defaults);
    const input = "Contact alice@example.com for info";
    const r = applyPolicy(input, patterns);
    expect(r.blocked).toBe(false);
    expect(r.output).toBe("Contact [REDACTED:email] for info");
    expect(r.matches.length).toBe(1);
    expect(r.matches[0]!.patternName).toBe("email");
  });

  it("blocks on JWT", () => {
    const patterns = compilePatterns(defaults);
    const jwt =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    const r = applyPolicy(`token=${jwt}`, patterns);
    expect(r.blocked).toBe(true);
  });

  it("blocks AWS access key", () => {
    const patterns = compilePatterns(defaults);
    const r = applyPolicy("AKIAIOSFODNN7EXAMPLE", patterns);
    expect(r.blocked).toBe(true);
  });

  it("blocks private key header", () => {
    const patterns = compilePatterns(defaults);
    const r = applyPolicy("-----BEGIN RSA PRIVATE KEY-----\nabc", patterns);
    expect(r.blocked).toBe(true);
  });

  it("redacts Vietnamese CCCD (12-digit number)", () => {
    const patterns = compilePatterns(defaults);
    const r = applyPolicy("CCCD 012345678901 here", patterns);
    expect(r.blocked).toBe(false);
    expect(r.output).toContain("[REDACTED:cccd_vn]");
  });

  it("respects per-pattern custom replacement", () => {
    const patterns = compilePatterns([
      {
        name: "email",
        regex: "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}",
        policy: "redact",
        replacement: "<email>",
      },
    ]);
    const r = applyPolicy("x@y.com", patterns);
    expect(r.output).toBe("<email>");
  });

  it("rejects ReDoS-prone patterns via safe-regex", () => {
    expect(() =>
      compilePatterns([
        { name: "bad", regex: "(a+)+$", policy: "redact" },
      ]),
    ).toThrow(/safe-regex/);
  });

  it("scan returns all matches even for the same pattern", () => {
    const patterns = compilePatterns(defaults);
    const matches = scan("a@b.com and c@d.org", patterns);
    expect(matches.filter((m) => m.patternName === "email").length).toBe(2);
  });
});

describe("redactAnthropicRequest", () => {
  it("walks system + messages[].content", () => {
    const patterns = compilePatterns(defaults);
    const body = {
      system: "Admin: root@corp.local",
      messages: [
        { role: "user", content: "My email is foo@bar.com" },
        {
          role: "assistant",
          content: [
            { type: "text", text: "ack: baz@qux.dev" },
          ],
        },
      ],
    };
    const r = redactAnthropicRequest(body, patterns);
    expect(r.blocked).toBe(false);
    expect(r.body.system).toContain("[REDACTED:email]");
    const msg0 = r.body.messages![0]!;
    expect(typeof msg0.content === "string" ? msg0.content : "").toContain(
      "[REDACTED:email]",
    );
    const msg1 = r.body.messages![1]!;
    const blocks = Array.isArray(msg1.content) ? msg1.content : [];
    expect((blocks[0] as { text?: string }).text).toContain(
      "[REDACTED:email]",
    );
  });

  it("reports blocked=true when a block pattern appears", () => {
    const patterns = compilePatterns(defaults);
    const body = {
      messages: [
        {
          role: "user",
          content:
            "key=AKIAIOSFODNN7EXAMPLE",
        },
      ],
    };
    const r = redactAnthropicRequest(body, patterns);
    expect(r.blocked).toBe(true);
    expect(r.blockedReasons).toContain("aws_access_key");
  });
});

describe("redactStreamingChunk", () => {
  it("redacts email inside SSE delta.text", () => {
    const patterns = compilePatterns(defaults);
    const chunk = [
      "event: content_block_delta",
      `data: ${JSON.stringify({
        type: "content_block_delta",
        delta: { type: "text_delta", text: "hi alice@example.com" },
      })}`,
    ].join("\n");
    const r = redactStreamingChunk(chunk, patterns);
    expect(r.output).toContain("[REDACTED:email]");
  });

  it("passes malformed data lines through unchanged", () => {
    const patterns = compilePatterns(defaults);
    const chunk = "data: {not-json\n";
    const r = redactStreamingChunk(chunk, patterns);
    expect(r.output).toBe("data: {not-json\n");
  });
});
