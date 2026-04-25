/**
 * AST detection lane (B7, behind config.astDlp.enabled / OMC_PROXY_AST_DLP=1).
 *
 * Detects internal package/module identifiers inside fenced code blocks and
 * tokenises them via the shared TokenVault so references to internal
 * TypeScript/JavaScript, Python, and Java modules don't egress.
 *
 * Supported fenced languages: typescript, ts, tsx, javascript, js, jsx,
 *                             python, py, java.
 *
 * What gets tokenised (classifier INTERNAL_PACKAGE):
 *   - TS/JS:  import/export `from "..."`, bare side-effect `import "..."`,
 *             CommonJS `require("...")`, dynamic `import("...")`.
 *   - Python: `from x.y import z`, `import x.y`, `import x as y`.
 *             (Relative imports `from . import z` are skipped — no leak.)
 *   - Java:   `import x.y.Class;`, `import static x.y.Class.member;`.
 *
 * Parse failure = silent pass-through. Non-allowlisted public packages
 * (React, numpy, java.util, etc.) are preserved.
 *
 * Integration contract: runs in applyPolicy Pass 0 alongside SqlLane. Both
 * structural lanes produce a masked `output`; regex/dict lanes then scan
 * the combined output with valid offsets.
 */

import { parse, Lang, type SgNode, type Edit } from "@ast-grep/napi";
import type { DlpMatch } from "./dlp.js";
import type { TokenVault } from "./vault.js";

export type AstLaneLanguage = "typescript" | "javascript" | "python" | "java";

export interface AstLaneConfig {
  enabled: boolean;
  languages: AstLaneLanguage[];
}

export interface AstLaneOptions {
  convId: string;
  vault: TokenVault;
}

export interface AstLaneResult {
  output: string;
  matches: DlpMatch[];
}

interface FencedRegion {
  start: number;
  end: number;
  lang: AstLaneLanguage;
}

// Fence-tag → canonical language.
const LANG_TAG_MAP: Record<string, AstLaneLanguage> = {
  typescript: "typescript",
  ts: "typescript",
  tsx: "typescript", // handled by Tsx parser
  javascript: "javascript",
  js: "javascript",
  jsx: "javascript", // handled by Tsx parser
  python: "python",
  py: "python",
  java: "java",
};

const PLACEHOLDER_TOKEN_RE = /^[A-Z][A-Z0-9_]*_\d{2,3}$/;

export class AstLane {
  private readonly config: AstLaneConfig;
  private readonly enabledLangs: Set<AstLaneLanguage>;

  constructor(config: AstLaneConfig) {
    this.config = config;
    this.enabledLangs = new Set(config.languages);
  }

  apply(text: string, opts: AstLaneOptions): AstLaneResult {
    if (!this.config.enabled) return { output: text, matches: [] };
    if (!text || text.length === 0) return { output: text, matches: [] };

    const regions = detectFencedRegions(text, this.enabledLangs);
    if (regions.length === 0) return { output: text, matches: [] };

    const matches: DlpMatch[] = [];
    // Splice in reverse so earlier regions keep their offsets.
    const descending = [...regions].sort((a, b) => b.start - a.start);
    let output = text;
    for (const r of descending) {
      const code = output.slice(r.start, r.end);
      const masked = this.maskRegion(code, r.lang, opts, matches, r);
      if (masked !== code) {
        output = output.slice(0, r.start) + masked + output.slice(r.end);
      }
    }
    return { output, matches };
  }

  private maskRegion(
    code: string,
    lang: AstLaneLanguage,
    opts: AstLaneOptions,
    matches: DlpMatch[],
    region: FencedRegion,
  ): string {
    let root: SgNode;
    try {
      root = parse(languageToAstGrep(lang), code).root();
    } catch {
      return code;
    }

    const hits = collectImportHits(root, lang);
    if (hits.length === 0) return code;

    const edits: Edit[] = [];
    for (const h of hits) {
      if (isPublicPath(h.path, lang)) continue;
      const token = opts.vault.issue(opts.convId, "INTERNAL_PACKAGE", h.path);
      edits.push({
        startPos: h.replaceStart,
        endPos: h.replaceEnd,
        insertedText: h.quoted ? `${h.quoteChar}${token}${h.quoteChar}` : token,
      });
      matches.push({
        patternName: "ast:internal_package",
        policy: "tokenize",
        start: region.start,
        end: region.end,
        sample: maskSample(h.path),
      });
    }

    if (edits.length === 0) return code;
    try {
      return root.commitEdits(edits);
    } catch {
      // Any commit-time failure is a silent no-op; we do not want to risk
      // sending a half-edited corrupted code block upstream.
      // Roll back sample matches to avoid misleading audit.
      matches.length -= edits.length;
      return code;
    }
  }
}

interface ImportHit {
  /** The canonical module path (quotes stripped for TS/JS). */
  path: string;
  /** Byte offset of the first char to replace (quote included for TS/JS). */
  replaceStart: number;
  /** Byte offset past the last char to replace (closing quote for TS/JS). */
  replaceEnd: number;
  /** True if the replaced span is a quoted string literal (TS/JS). */
  quoted: boolean;
  /** Quote character preserved when re-emitting (TS/JS only). */
  quoteChar: string;
}

function collectImportHits(root: SgNode, lang: AstLaneLanguage): ImportHit[] {
  if (lang === "typescript" || lang === "javascript") {
    return collectJsImports(root);
  }
  if (lang === "python") {
    return collectPythonImports(root);
  }
  if (lang === "java") {
    return collectJavaImports(root);
  }
  return [];
}

function collectJsImports(root: SgNode): ImportHit[] {
  const out: ImportHit[] = [];
  const strs = root.findAll("$STR").filter((n) => n.kind() === "string");
  for (const s of strs) {
    const raw = s.text(); // includes quotes: "foo" or 'foo'
    if (raw.length < 2) continue;
    const q = raw[0];
    if (q !== '"' && q !== "'" && q !== "`") continue;
    const inside = raw.slice(1, -1);
    if (isPlaceholderToken(inside)) continue;

    const parent = s.parent();
    const parentKind = parent?.kind();
    let inInlineImport = false;

    if (parentKind === "import_statement" || parentKind === "export_statement") {
      inInlineImport = true;
    } else if (parentKind === "arguments") {
      // require("...") or import("...")
      const call = parent?.parent();
      if (call && call.kind() === "call_expression") {
        const fn = call.child(0);
        const fnText = fn?.text();
        if (fnText === "require" || fnText === "import") {
          inInlineImport = true;
        }
      }
    }

    if (!inInlineImport) continue;
    const range = s.range();
    out.push({
      path: inside,
      replaceStart: range.start.index,
      replaceEnd: range.end.index,
      quoted: true,
      quoteChar: q,
    });
  }
  return out;
}

function collectPythonImports(root: SgNode): ImportHit[] {
  const out: ImportHit[] = [];
  // `import x.y` and `import x as y` live under `import_statement` with one or
  // more `dotted_name` or `aliased_import` children.
  const imports = root
    .findAll("$X")
    .filter(
      (n) =>
        n.kind() === "import_statement" || n.kind() === "import_from_statement",
    );
  for (const imp of imports) {
    if (imp.kind() === "import_statement") {
      for (const child of imp.children()) {
        if (child.kind() === "dotted_name") {
          pushPythonDotted(child, out);
        } else if (child.kind() === "aliased_import") {
          const inner = child.child(0);
          if (inner && inner.kind() === "dotted_name") {
            pushPythonDotted(inner, out);
          }
        }
      }
    } else {
      // `from X import Y` — only the module (X) side is a path to mask.
      // Relative imports (`from . import z`) use `relative_import` kind; skip.
      for (const child of imp.children()) {
        if (child.kind() === "dotted_name") {
          pushPythonDotted(child, out);
          break;
        }
        if (child.kind() === "relative_import") {
          break; // no module path to leak
        }
      }
    }
  }
  return out;
}

function pushPythonDotted(node: SgNode, out: ImportHit[]): void {
  const text = node.text();
  if (isPlaceholderToken(text)) return;
  const range = node.range();
  out.push({
    path: text,
    replaceStart: range.start.index,
    replaceEnd: range.end.index,
    quoted: false,
    quoteChar: "",
  });
}

function collectJavaImports(root: SgNode): ImportHit[] {
  const out: ImportHit[] = [];
  const imports = root
    .findAll("$X")
    .filter((n) => n.kind() === "import_declaration");
  for (const imp of imports) {
    for (const child of imp.children()) {
      if (child.kind() === "scoped_identifier") {
        const text = child.text();
        if (isPlaceholderToken(text)) continue;
        const range = child.range();
        out.push({
          path: text,
          replaceStart: range.start.index,
          replaceEnd: range.end.index,
          quoted: false,
          quoteChar: "",
        });
      }
    }
  }
  return out;
}

// --- Public-path allowlists ------------------------------------------------

// Exact or prefixed matches (prefix ends with "/" for scoped). An exact match
// also matches subpaths: "react" matches "react/jsx-runtime".
const PUBLIC_JS: string[] = [
  // Node stdlib
  "fs",
  "path",
  "os",
  "crypto",
  "http",
  "https",
  "http2",
  "stream",
  "util",
  "events",
  "url",
  "buffer",
  "child_process",
  "cluster",
  "dgram",
  "dns",
  "net",
  "tls",
  "querystring",
  "readline",
  "tty",
  "vm",
  "zlib",
  "assert",
  "console",
  "process",
  "module",
  "worker_threads",
  "perf_hooks",
  "timers",
  "string_decoder",
  "diagnostics_channel",
  // Popular libs (broad strokes; users can extend via dictionary entries)
  "react",
  "react-dom",
  "react-native",
  "next",
  "vue",
  "svelte",
  "express",
  "koa",
  "fastify",
  "lodash",
  "underscore",
  "ramda",
  "moment",
  "date-fns",
  "dayjs",
  "axios",
  "node-fetch",
  "undici",
  "zod",
  "joi",
  "yup",
  "ajv",
  "vitest",
  "jest",
  "mocha",
  "chai",
  "tap",
  "typescript",
  "esbuild",
  "rollup",
  "webpack",
  "vite",
  "tsx",
  "chalk",
  "commander",
  "yargs",
  "inquirer",
  "picocolors",
  "rxjs",
  "redux",
  "@reduxjs/toolkit",
  "classnames",
  "tslib",
  // Scoped prefixes (ending with "/")
  "@types/",
  "@anthropic-ai/",
  "@modelcontextprotocol/",
  "@ast-grep/",
  "@vitest/",
  "@typescript-eslint/",
  "@eslint/",
  "@babel/",
  "@rollup/",
];

const PUBLIC_PY: string[] = [
  // stdlib (partial — add as needed)
  "os",
  "sys",
  "re",
  "json",
  "datetime",
  "typing",
  "collections",
  "pathlib",
  "functools",
  "itertools",
  "operator",
  "copy",
  "pickle",
  "struct",
  "math",
  "random",
  "time",
  "threading",
  "asyncio",
  "logging",
  "warnings",
  "io",
  "subprocess",
  "shutil",
  "tempfile",
  "glob",
  "csv",
  "html",
  "xml",
  "unittest",
  "dataclasses",
  "enum",
  "abc",
  "contextlib",
  "hashlib",
  "hmac",
  "secrets",
  "uuid",
  "base64",
  "urllib",
  "http",
  "socket",
  "ssl",
  "platform",
  "tracebook",
  "traceback",
  // Popular packages
  "numpy",
  "pandas",
  "requests",
  "pydantic",
  "fastapi",
  "starlette",
  "uvicorn",
  "django",
  "flask",
  "sqlalchemy",
  "alembic",
  "pytest",
  "click",
  "typer",
  "httpx",
  "aiohttp",
  "boto3",
  "redis",
  "celery",
  "pillow",
  "matplotlib",
  "scipy",
  "sklearn",
  "tensorflow",
  "torch",
  "transformers",
  "openai",
  "anthropic",
];

const PUBLIC_JAVA: string[] = [
  "java.",
  "javax.",
  "jdk.",
  "sun.",
  "org.junit.",
  "org.springframework.",
  "org.apache.",
  "com.google.common.",
  "com.fasterxml.jackson.",
  "io.micrometer.",
  "lombok.",
  "kotlin.",
  "kotlinx.",
];

function isPublicPath(path: string, lang: AstLaneLanguage): boolean {
  if (!path) return false;
  // Relative / absolute file paths are always internal (no public convention).
  if (path.startsWith("./") || path.startsWith("../") || path.startsWith("/"))
    return false;

  const list =
    lang === "typescript" || lang === "javascript"
      ? PUBLIC_JS
      : lang === "python"
        ? PUBLIC_PY
        : PUBLIC_JAVA;

  for (const pub of list) {
    if (pub.endsWith("/") || pub.endsWith(".")) {
      if (path.startsWith(pub)) return true;
    } else if (path === pub || path.startsWith(pub + "/") || path.startsWith(pub + ".")) {
      return true;
    }
  }
  return false;
}

function isPlaceholderToken(s: string): boolean {
  return PLACEHOLDER_TOKEN_RE.test(s);
}

function maskSample(s: string): string {
  if (s.length <= 4) return "*".repeat(s.length);
  return s.slice(0, 2) + "***" + s.slice(-1);
}

function languageToAstGrep(lang: AstLaneLanguage): Lang {
  switch (lang) {
    case "typescript":
      return Lang.Tsx;
    case "javascript":
      return Lang.Tsx;
    case "python":
      return Lang.Python;
    case "java":
      return Lang.Java;
  }
}

export function detectFencedRegions(
  text: string,
  enabledLangs: Set<AstLaneLanguage>,
): FencedRegion[] {
  const regions: FencedRegion[] = [];
  const fenceRe =
    /```([a-zA-Z]+)[ \t]*\r?\n([\s\S]*?)\r?\n```/g;
  let m: RegExpExecArray | null;
  while ((m = fenceRe.exec(text)) !== null) {
    const tag = m[1].toLowerCase();
    const lang = LANG_TAG_MAP[tag];
    if (!lang) continue;
    if (!enabledLangs.has(lang)) continue;
    const body = m[2];
    const bodyStart = m.index + m[0].indexOf(body, m[1].length);
    regions.push({
      start: bodyStart,
      end: bodyStart + body.length,
      lang,
    });
  }
  return regions.sort((a, b) => a.start - b.start);
}
