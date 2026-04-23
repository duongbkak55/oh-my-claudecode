import { describe, it, expect } from "vitest";
import {
  AstLane,
  detectFencedRegions,
  type AstLaneLanguage,
} from "../ast-lane.js";
import { InProcessTokenVault } from "../vault.js";

function makeLane(
  overrides: Partial<{
    enabled: boolean;
    languages: AstLaneLanguage[];
  }> = {},
): AstLane {
  return new AstLane({
    enabled: overrides.enabled ?? true,
    languages:
      overrides.languages ?? ["typescript", "javascript", "python", "java"],
  });
}

function makeVault() {
  const vault = new InProcessTokenVault();
  return { vault, convId: "conv-test" };
}

function fenced(lang: string, body: string): string {
  return "```" + lang + "\n" + body + "\n```";
}

describe("AstLane region detection", () => {
  const allLangs = new Set<AstLaneLanguage>([
    "typescript",
    "javascript",
    "python",
    "java",
  ]);

  it("detects ```typescript and ```ts as typescript", () => {
    const r1 = detectFencedRegions(fenced("typescript", "x"), allLangs);
    const r2 = detectFencedRegions(fenced("ts", "x"), allLangs);
    expect(r1.length).toBe(1);
    expect(r2.length).toBe(1);
    expect(r1[0]!.lang).toBe("typescript");
    expect(r2[0]!.lang).toBe("typescript");
  });

  it("detects ```python and ```py as python", () => {
    const r1 = detectFencedRegions(fenced("python", "x"), allLangs);
    const r2 = detectFencedRegions(fenced("py", "x"), allLangs);
    expect(r1[0]!.lang).toBe("python");
    expect(r2[0]!.lang).toBe("python");
  });

  it("ignores unknown language tags", () => {
    const r = detectFencedRegions(fenced("ruby", "puts 'x'"), allLangs);
    expect(r.length).toBe(0);
  });

  it("respects enabledLangs filter", () => {
    const onlyPy = new Set<AstLaneLanguage>(["python"]);
    const input = fenced("typescript", "import x from 'y';") +
      "\n" +
      fenced("python", "import x");
    const r = detectFencedRegions(input, onlyPy);
    expect(r.length).toBe(1);
    expect(r[0]!.lang).toBe("python");
  });
});

describe("AstLane — TypeScript / JavaScript", () => {
  it("tokenises an internal scoped package import", () => {
    const lane = makeLane();
    const vault = makeVault();
    const input = fenced("typescript", 'import { foo } from "@vng/auth";');
    const r = lane.apply(input, vault);
    expect(r.output).toContain("INTERNAL_PACKAGE_01");
    expect(r.output).not.toContain("@vng/auth");
    expect(vault.vault.lookup(vault.convId, "INTERNAL_PACKAGE_01")).toBe(
      "@vng/auth",
    );
  });

  it("does NOT mask a well-known public package (react)", () => {
    const lane = makeLane();
    const vault = makeVault();
    const input = fenced("typescript", 'import React from "react";');
    const r = lane.apply(input, vault);
    expect(r.output).toContain("react");
    expect(r.matches.length).toBe(0);
  });

  it("masks relative imports as internal", () => {
    const lane = makeLane();
    const vault = makeVault();
    const input = fenced("javascript", 'const x = require("./helpers/util");');
    const r = lane.apply(input, vault);
    expect(r.output).not.toContain("./helpers/util");
    expect(r.output).toContain("INTERNAL_PACKAGE_01");
  });

  it("masks dynamic import() call", () => {
    const lane = makeLane();
    const vault = makeVault();
    const input = fenced(
      "typescript",
      'const mod = await import("@internal/lazy");',
    );
    const r = lane.apply(input, vault);
    expect(r.output).not.toContain("@internal/lazy");
    expect(r.output).toContain("INTERNAL_PACKAGE_01");
  });

  it("masks side-effect bare import", () => {
    const lane = makeLane();
    const vault = makeVault();
    const input = fenced("javascript", 'import "./polyfills/internal";');
    const r = lane.apply(input, vault);
    expect(r.output).not.toContain("./polyfills/internal");
  });

  it("masks re-export source path", () => {
    const lane = makeLane();
    const vault = makeVault();
    const input = fenced(
      "typescript",
      'export { thing } from "@company/sdk";',
    );
    const r = lane.apply(input, vault);
    expect(r.output).not.toContain("@company/sdk");
  });

  it("preserves quote character (single vs double)", () => {
    const lane = makeLane();
    const vault = makeVault();
    const input = fenced("javascript", "import foo from '@vng/auth';");
    const r = lane.apply(input, vault);
    // Single quotes preserved
    expect(r.output).toMatch(/from 'INTERNAL_PACKAGE_\d+'/);
  });

  it("does not treat non-import string literals as imports", () => {
    const lane = makeLane();
    const vault = makeVault();
    const input = fenced(
      "typescript",
      'const greeting = "@vng/auth"; console.log(greeting);',
    );
    const r = lane.apply(input, vault);
    expect(r.output).toContain("@vng/auth");
    expect(r.matches.length).toBe(0);
  });

  it("skips existing placeholder tokens (idempotence)", () => {
    const lane = makeLane();
    const vault = makeVault();
    const input = fenced("typescript", 'import x from "INTERNAL_PACKAGE_01";');
    const r = lane.apply(input, vault);
    expect(r.output).toBe(input);
    expect(r.matches.length).toBe(0);
  });
});

describe("AstLane — Python", () => {
  it("masks `from internal.module import X`", () => {
    const lane = makeLane();
    const vault = makeVault();
    const input = fenced("python", "from myapp.auth import User");
    const r = lane.apply(input, vault);
    expect(r.output).not.toContain("myapp.auth");
    expect(r.output).toContain("INTERNAL_PACKAGE_01");
  });

  it("masks `import module_name`", () => {
    const lane = makeLane();
    const vault = makeVault();
    const input = fenced("py", "import myapp");
    const r = lane.apply(input, vault);
    expect(r.output).not.toContain("import myapp");
    expect(r.output).toContain("INTERNAL_PACKAGE_01");
  });

  it("masks `import x.y as z` (aliased)", () => {
    const lane = makeLane();
    const vault = makeVault();
    const input = fenced("python", "import myapp.helpers as h");
    const r = lane.apply(input, vault);
    expect(r.output).not.toContain("myapp.helpers");
    expect(r.output).toMatch(/import INTERNAL_PACKAGE_\d+ as h/);
  });

  it("does NOT mask stdlib imports", () => {
    const lane = makeLane();
    const vault = makeVault();
    const input = fenced("python", "import os\nimport sys\nimport json");
    const r = lane.apply(input, vault);
    expect(r.output).toContain("import os");
    expect(r.output).toContain("import sys");
    expect(r.output).toContain("import json");
    expect(r.matches.length).toBe(0);
  });

  it("does NOT mask well-known third-party (numpy, pandas)", () => {
    const lane = makeLane();
    const vault = makeVault();
    const input = fenced(
      "python",
      "import numpy as np\nimport pandas as pd\nfrom fastapi import FastAPI",
    );
    const r = lane.apply(input, vault);
    expect(r.output).toContain("numpy");
    expect(r.output).toContain("pandas");
    expect(r.output).toContain("fastapi");
  });

  it("does NOT leak names via relative import (from . import x)", () => {
    const lane = makeLane();
    const vault = makeVault();
    const input = fenced("python", "from . import helpers");
    const r = lane.apply(input, vault);
    // Relative imports have no module path to leak; should be no-op.
    expect(r.output).toBe(input);
  });
});

describe("AstLane — Java", () => {
  it("masks internal package imports", () => {
    const lane = makeLane();
    const vault = makeVault();
    const input = fenced("java", "import com.vng.auth.User;");
    const r = lane.apply(input, vault);
    expect(r.output).not.toContain("com.vng.auth.User");
    expect(r.output).toContain("INTERNAL_PACKAGE_01");
  });

  it("does NOT mask java.* / javax.* stdlib", () => {
    const lane = makeLane();
    const vault = makeVault();
    const input = fenced(
      "java",
      "import java.util.List;\nimport javax.servlet.http.HttpServletRequest;",
    );
    const r = lane.apply(input, vault);
    expect(r.output).toContain("java.util.List");
    expect(r.output).toContain("javax.servlet.http.HttpServletRequest");
    expect(r.matches.length).toBe(0);
  });

  it("does NOT mask well-known Spring / JUnit imports", () => {
    const lane = makeLane();
    const vault = makeVault();
    const input = fenced(
      "java",
      "import org.springframework.web.bind.annotation.RestController;\nimport org.junit.jupiter.api.Test;",
    );
    const r = lane.apply(input, vault);
    expect(r.output).toContain("org.springframework");
    expect(r.output).toContain("org.junit");
  });

  it("handles `import static`", () => {
    const lane = makeLane();
    const vault = makeVault();
    const input = fenced(
      "java",
      "import static com.acme.Util.doThing;",
    );
    const r = lane.apply(input, vault);
    expect(r.output).toMatch(/import static INTERNAL_PACKAGE_\d+;/);
  });
});

describe("AstLane — general contract", () => {
  it("is a no-op when enabled=false", () => {
    const lane = makeLane({ enabled: false });
    const vault = makeVault();
    const input = fenced("typescript", 'import x from "@vng/auth";');
    const r = lane.apply(input, vault);
    expect(r.output).toBe(input);
    expect(r.matches.length).toBe(0);
  });

  it("is a no-op when the fence language is disabled", () => {
    const lane = makeLane({ languages: ["python"] });
    const vault = makeVault();
    const input = fenced("typescript", 'import x from "@vng/auth";');
    const r = lane.apply(input, vault);
    expect(r.output).toBe(input);
    expect(r.matches.length).toBe(0);
  });

  it("passes through malformed source silently", () => {
    const lane = makeLane();
    const vault = makeVault();
    const input = fenced("typescript", "import from @@@ (((;");
    const r = lane.apply(input, vault);
    // Output may be identical OR have partial parse; critically, it must not
    // corrupt or throw.
    expect(() => lane.apply(input, vault)).not.toThrow();
    expect(r.matches.length).toBeLessThanOrEqual(1);
  });

  it("does not touch text outside fenced blocks", () => {
    const lane = makeLane();
    const vault = makeVault();
    const input = 'Here is a plain mention of @vng/auth in prose. Also `import x from "@vng/internal"` inline (not a fenced block).';
    const r = lane.apply(input, vault);
    expect(r.output).toBe(input);
    expect(r.matches.length).toBe(0);
  });

  it("handles multiple languages in one prompt", () => {
    const lane = makeLane();
    const vault = makeVault();
    const input =
      fenced("typescript", 'import x from "@internal/ts";') +
      "\n" +
      fenced("python", "from internal_py import foo") +
      "\n" +
      fenced("java", "import com.internal.Cls;");
    const r = lane.apply(input, vault);
    expect(r.matches.length).toBe(3);
    const tokens = vault.vault.listTokensForConv(vault.convId);
    expect(tokens.length).toBe(3);
  });

  it("deduplicates: same internal path in two fenced blocks gets one token", () => {
    const lane = makeLane();
    const vault = makeVault();
    const input =
      fenced("typescript", 'import { a } from "@vng/auth";') +
      "\n\n" +
      fenced("typescript", 'import { b } from "@vng/auth";');
    const r = lane.apply(input, vault);
    // Vault dedup: one vault entry.
    expect(vault.vault.listTokensForConv(vault.convId).length).toBe(1);
    // But two edit matches.
    expect(r.matches.length).toBe(2);
  });

  it("does not crash on empty input", () => {
    const lane = makeLane();
    const vault = makeVault();
    const r = lane.apply("", vault);
    expect(r.output).toBe("");
    expect(r.matches.length).toBe(0);
  });

  it("supports round-trip detokenise for a simple TS import", () => {
    const lane = makeLane();
    const vault = makeVault();
    const input = fenced("typescript", 'import x from "@vng/auth";');
    const r = lane.apply(input, vault);
    const token = vault.vault.listTokensForConv(vault.convId)[0]!;
    const original = vault.vault.lookup(vault.convId, token)!;
    const restored = r.output.replace(token, original);
    expect(restored).toBe(input);
  });
});
