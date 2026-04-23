import { describe, it, expect } from "vitest";
import { Dictionary } from "../dictionary.js";

describe("Dictionary (Aho-Corasick)", () => {
  it("matches an exact term anywhere in the text", () => {
    const d = new Dictionary([
      { term: "Project Bluefin", classifier: "CODENAME", policy: "tokenize" },
    ]);
    const r = d.scan("We discussed Project Bluefin with the team.");
    expect(r.length).toBe(1);
    expect(r[0]!.classifier).toBe("CODENAME");
    expect(r[0]!.start).toBe("We discussed ".length);
    expect(r[0]!.end).toBe("We discussed Project Bluefin".length);
  });

  it("longest-leftmost wins on overlapping terms", () => {
    const d = new Dictionary([
      { term: "Project", classifier: "CODENAME", policy: "tokenize" },
      { term: "Project Bluefin", classifier: "CODENAME", policy: "tokenize" },
    ]);
    const r = d.scan("The Project Bluefin release");
    expect(r.length).toBe(1);
    expect(r[0]!.end - r[0]!.start).toBe("Project Bluefin".length);
  });

  it("word-boundary: 'Vietcombank' does NOT match inside 'Vietcombanking'", () => {
    const d = new Dictionary([
      { term: "Vietcombank", classifier: "PARTNER_NAME", policy: "tokenize" },
    ]);
    const r = d.scan("Integrating with Vietcombanking service.");
    expect(r.length).toBe(0);
    const r2 = d.scan("Integrating with Vietcombank service.");
    expect(r2.length).toBe(1);
  });

  it("case-insensitive for PARTNER_NAME", () => {
    const d = new Dictionary([
      { term: "Vietcombank", classifier: "PARTNER_NAME", policy: "tokenize" },
    ]);
    const r = d.scan("vietcombank and VIETCOMBANK both match");
    expect(r.length).toBe(2);
    expect(r[0]!.classifier).toBe("PARTNER_NAME");
    expect(r[1]!.classifier).toBe("PARTNER_NAME");
  });

  it("case-sensitive for INTERNAL_PACKAGE", () => {
    const d = new Dictionary([
      {
        term: "@vng/zalo-pay-internal-sdk",
        classifier: "INTERNAL_PACKAGE",
        policy: "tokenize",
      },
    ]);
    const hit = d.scan("import '@vng/zalo-pay-internal-sdk';");
    expect(hit.length).toBe(1);
    const miss = d.scan("import '@VNG/ZALO-PAY-INTERNAL-SDK';");
    expect(miss.length).toBe(0);
  });

  it("reload replaces the ruleset", () => {
    const d = new Dictionary([
      { term: "alpha", classifier: "CODENAME", policy: "tokenize" },
    ]);
    expect(d.scan("alpha").length).toBe(1);
    d.reload([
      { term: "beta", classifier: "CODENAME", policy: "tokenize" },
    ]);
    expect(d.scan("alpha").length).toBe(0);
    expect(d.scan("beta").length).toBe(1);
  });
});
