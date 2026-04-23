import { describe, it, expect } from "vitest";
import {
  applyPolicy,
  compilePatterns,
  detokenize,
  redactAnthropicRequest,
  redactStreamingChunk,
  scan,
  SseDetokenizer,
  SseRedactor,
  type DlpRawPattern,
} from "../dlp.js";
import { InProcessTokenVault } from "../vault.js";

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

describe("redactAnthropicRequest extended coverage", () => {
  it("redacts secrets embedded in tools[].description", () => {
    const patterns = compilePatterns(defaults);
    const body = {
      tools: [
        {
          name: "fetcher",
          description: "contact admin at admin@corp.local to get access",
        },
      ],
    };
    const r = redactAnthropicRequest(body, patterns);
    const desc = (r.body.tools![0] as unknown as { description: string })
      .description;
    expect(desc).toContain("[REDACTED:email]");
    expect(desc).not.toContain("admin@corp.local");
  });

  it("recursively redacts strings inside tools[].input_schema", () => {
    const patterns = compilePatterns(defaults);
    const body = {
      tools: [
        {
          name: "fetcher",
          input_schema: {
            type: "object",
            properties: {
              q: {
                type: "string",
                description: "default user is bob@example.com",
              },
            },
          },
        },
      ],
    };
    const r = redactAnthropicRequest(body, patterns);
    const schema = (
      r.body.tools![0] as unknown as {
        input_schema: { properties: { q: { description: string } } };
      }
    ).input_schema;
    expect(schema.properties.q.description).toContain("[REDACTED:email]");
    expect(schema.properties.q.description).not.toContain("bob@example.com");
  });

  it("redacts secrets in nested tool_result.content[].text", () => {
    const patterns = compilePatterns(defaults);
    const body = {
      messages: [
        {
          role: "user",
          content: [
            {
              type: "tool_result",
              tool_use_id: "tu_1",
              content: [
                { type: "text", text: "here is your email: x@y.com" },
              ],
            },
          ],
        },
      ],
    };
    const r = redactAnthropicRequest(body, patterns);
    const msg = r.body.messages![0]!;
    const blocks = Array.isArray(msg.content) ? msg.content : [];
    const tr = blocks[0] as { content?: Array<{ text?: string }> };
    expect(tr.content?.[0]?.text).toContain("[REDACTED:email]");
    expect(tr.content?.[0]?.text).not.toContain("x@y.com");
  });

  it("redacts secrets in system array form", () => {
    const patterns = compilePatterns(defaults);
    const body = {
      system: [
        { type: "text", text: "admin: foo@bar.baz" },
      ],
    };
    const r = redactAnthropicRequest(body, patterns);
    const sys = Array.isArray(r.body.system) ? r.body.system : [];
    expect((sys[0] as { text?: string }).text).toContain("[REDACTED:email]");
  });

  it("does NOT scan structural keys (name/type/id/etc.) — no false positives on a tool named 'sk-test-tool'", () => {
    const patterns = compilePatterns(defaults);
    const body = {
      tools: [
        {
          name: "sk-test-tool-abcdefghijklmnopqrstuv",
          description: "ok",
        },
      ],
    };
    const r = redactAnthropicRequest(body, patterns);
    expect(r.blocked).toBe(false);
    // The tool name string is preserved as-is (it's a structural key).
    expect((r.body.tools![0] as { name: string }).name).toBe(
      "sk-test-tool-abcdefghijklmnopqrstuv",
    );
  });
});

describe("SseRedactor (rolling, cross-frame)", () => {
  it("blocks an sk- secret split across chunk boundaries", () => {
    const patterns = compilePatterns([
      ...defaults,
      {
        name: "generic_api_key",
        regex: "sk-[A-Za-z0-9_-]{20,}",
        policy: "block",
      },
    ]);
    const r = new SseRedactor(patterns);
    const makeDelta = (text: string): string =>
      `event: content_block_delta\ndata: ${JSON.stringify({
        type: "content_block_delta",
        index: 0,
        delta: { type: "text_delta", text },
      })}\n\n`;
    const chunks = [
      makeDelta("here goes sk-"),
      makeDelta("ant-"),
      makeDelta("abcdefghijklmnopqrstuvwxyz1234567890AAAA"),
    ];
    let all = "";
    let blocked = false;
    for (const c of chunks) {
      const res = r.push(c);
      all += res.emit;
      if (res.blocked) blocked = true;
    }
    if (!blocked) {
      const tail = r.flush();
      all += tail.emit;
      blocked = blocked || tail.blocked;
    }
    expect(blocked).toBe(true);
    // The raw secret must not leak through.
    expect(all).not.toContain(
      "sk-ant-abcdefghijklmnopqrstuvwxyz1234567890",
    );
    expect(all).toContain("dlp_blocked");
  });

  it("redacts JWT in delta.thinking", () => {
    const patterns = compilePatterns(defaults);
    const r = new SseRedactor(patterns);
    const jwt =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    const frame = `event: content_block_delta\ndata: ${JSON.stringify({
      type: "content_block_delta",
      index: 0,
      delta: { type: "thinking_delta", thinking: `contemplating ${jwt} hmm` },
    })}\n\n`;
    const pushed = r.push(frame);
    const tail = r.flush();
    const out = pushed.emit + tail.emit;
    expect(out).not.toContain(jwt);
    expect(pushed.blocked || tail.blocked).toBe(true);
  });

  it("redacts email in delta.partial_json", () => {
    const patterns = compilePatterns(defaults);
    const r = new SseRedactor(patterns);
    const frame = `event: content_block_delta\ndata: ${JSON.stringify({
      type: "content_block_delta",
      index: 0,
      delta: {
        type: "input_json_delta",
        partial_json: '{"who":"me@you.com"}',
      },
    })}\n\n`;
    const pushed = r.push(frame);
    const tail = r.flush();
    const out = pushed.emit + tail.emit;
    expect(out).toContain("[REDACTED:email]");
    expect(out).not.toContain("me@you.com");
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

describe("tokenize policy + detokenize round-trip", () => {
  const tokenizingPatterns: DlpRawPattern[] = [
    {
      name: "email",
      regex: "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}",
      policy: "tokenize",
    },
  ];

  it("tokenize policy issues tokens and substitutes the match", () => {
    const patterns = compilePatterns(tokenizingPatterns);
    const vault = new InProcessTokenVault();
    const r = applyPolicy(
      "email alice@example.com and bob@example.com please",
      patterns,
      { vault: { convId: "c1", vault } },
    );
    expect(r.blocked).toBe(false);
    expect(r.output).toContain("EMAIL_01");
    expect(r.output).toContain("EMAIL_02");
    expect(r.output).not.toContain("alice@example.com");
    expect(vault.lookup("c1", "EMAIL_01")).toBe("alice@example.com");
    expect(vault.lookup("c1", "EMAIL_02")).toBe("bob@example.com");
  });

  it("detokenize restores original values from the vault", () => {
    const vault = new InProcessTokenVault();
    vault.issue("c1", "email", "alice@example.com");
    const out = detokenize("Hi EMAIL_01, ping me.", "c1", vault);
    expect(out).toBe("Hi alice@example.com, ping me.");
  });

  it("unknown tokens pass through detokenize unchanged", () => {
    const vault = new InProcessTokenVault();
    const out = detokenize("unknown UNKNOWN_99 token", "c1", vault);
    expect(out).toBe("unknown UNKNOWN_99 token");
  });

  it("round-trip: tokenize -> upstream echoes token -> detokenize gives original", () => {
    const patterns = compilePatterns(tokenizingPatterns);
    const vault = new InProcessTokenVault();
    const req = applyPolicy(
      "my email is alice@example.com so please remember it",
      patterns,
      { vault: { convId: "conv-x", vault } },
    );
    // The token the model now sees:
    const token = req.output.match(/EMAIL_\d{2,3}/)![0];
    // Simulate upstream echoing the token back in a reply.
    const simulatedUpstream = `Sure, I will email you at ${token} shortly.`;
    const clientSees = detokenize(simulatedUpstream, "conv-x", vault);
    expect(clientSees).toBe(
      "Sure, I will email you at alice@example.com shortly.",
    );
  });

  it("SseDetokenizer restores tokens split across SSE deltas", () => {
    const vault = new InProcessTokenVault();
    vault.issue("c1", "email", "alice@example.com");
    const detok = new SseDetokenizer("c1", vault);
    const makeDelta = (text: string): string =>
      `event: content_block_delta\ndata: ${JSON.stringify({
        type: "content_block_delta",
        index: 0,
        delta: { type: "text_delta", text },
      })}\n\n`;
    const stop = `event: content_block_stop\ndata: ${JSON.stringify({
      type: "content_block_stop",
      index: 0,
    })}\n\n`;
    const parts = [makeDelta("hi "), makeDelta("EMA"), makeDelta("IL_01"), makeDelta(" ok"), stop];
    let out = "";
    for (const p of parts) out += detok.push(p).emit;
    out += detok.flush().emit;
    expect(out).toContain("alice@example.com");
    expect(out).not.toContain("EMAIL_01");
  });

  it("redactAnthropicRequest injects DLP preservation instruction into system when tokenizing", () => {
    const patterns = compilePatterns(tokenizingPatterns);
    const vault = new InProcessTokenVault();
    const r = redactAnthropicRequest(
      {
        system: "You are a helpful assistant.",
        messages: [{ role: "user", content: "email me at x@y.com" }],
      },
      patterns,
      { vault: { convId: "c1", vault } },
    );
    expect(typeof r.body.system).toBe("string");
    expect(r.body.system as string).toContain("[OMC-DLP]");
  });
});

