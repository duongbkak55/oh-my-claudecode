import { describe, it, expect } from "vitest";
import { InProcessTokenVault } from "../vault.js";

describe("InProcessTokenVault", () => {
  it("issue returns same token for same value within same conv", () => {
    const v = new InProcessTokenVault();
    const t1 = v.issue("c1", "email", "alice@example.com");
    const t2 = v.issue("c1", "email", "alice@example.com");
    expect(t1).toBe(t2);
    expect(t1).toBe("EMAIL_01");
  });

  it("different values get different sequential tokens per class", () => {
    const v = new InProcessTokenVault();
    const t1 = v.issue("c1", "email", "alice@example.com");
    const t2 = v.issue("c1", "email", "bob@example.com");
    const p1 = v.issue("c1", "phone", "+84 90 111 2222");
    expect(t1).toBe("EMAIL_01");
    expect(t2).toBe("EMAIL_02");
    expect(p1).toBe("PHONE_01");
  });

  it("different conv gets an independent token space for the same value", () => {
    const v = new InProcessTokenVault();
    const t1 = v.issue("c1", "email", "alice@example.com");
    const t2 = v.issue("c2", "email", "alice@example.com");
    expect(t1).toBe("EMAIL_01");
    expect(t2).toBe("EMAIL_01");
    expect(v.lookup("c1", "EMAIL_01")).toBe("alice@example.com");
    expect(v.lookup("c2", "EMAIL_01")).toBe("alice@example.com");
    expect(v.lookup("c1", "EMAIL_02")).toBeNull();
  });

  it("TTL expiry purges stale conversations", () => {
    let fakeNow = 1_000_000;
    const v = new InProcessTokenVault({
      ttlMs: 1000,
      now: () => fakeNow,
    });
    v.issue("c1", "email", "alice@example.com");
    expect(v.lookup("c1", "EMAIL_01")).toBe("alice@example.com");
    fakeNow += 5000;
    v.purgeExpired();
    expect(v.lookup("c1", "EMAIL_01")).toBeNull();
    expect(v.listTokensForConv("c1")).toEqual([]);
  });

  it("case-folds emails: Alice@X.com and alice@x.com collide", () => {
    const v = new InProcessTokenVault();
    const t1 = v.issue("c1", "email", "Alice@X.com");
    const t2 = v.issue("c1", "email", "alice@x.com");
    expect(t1).toBe(t2);
    expect(v.lookup("c1", t1)).toBe("Alice@X.com");
  });

  it("NFC-normalizes keys so decomposed/composed equivalents collide", () => {
    const v = new InProcessTokenVault();
    // composed é (U+00E9) vs decomposed "e" + U+0301 combining acute.
    const composed = "café@example.com";
    const decomposed = "café@example.com";
    expect(composed).not.toBe(decomposed);
    const t1 = v.issue("c1", "email", composed);
    const t2 = v.issue("c1", "email", decomposed);
    expect(t1).toBe(t2);
    expect(t1).toBe("EMAIL_01");
  });

  it("case-sensitive for INTERNAL_PACKAGE classifier", () => {
    const v = new InProcessTokenVault();
    const t1 = v.issue("c1", "INTERNAL_PACKAGE", "@VNG/zalo");
    const t2 = v.issue("c1", "INTERNAL_PACKAGE", "@vng/zalo");
    expect(t1).not.toBe(t2);
  });

  it("purge drops a single conversation", () => {
    const v = new InProcessTokenVault();
    v.issue("c1", "email", "a@b.com");
    v.issue("c2", "email", "c@d.com");
    v.purge("c1");
    expect(v.lookup("c1", "EMAIL_01")).toBeNull();
    expect(v.lookup("c2", "EMAIL_01")).toBe("c@d.com");
  });
});
