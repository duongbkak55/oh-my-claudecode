/**
 * SQL detection lane (B6, behind config.sqlDlp.enabled / OMC_PROXY_SQL_DLP=1).
 *
 * Detects SQL statements inside prompt text via two heuristics:
 *   1. Fenced code blocks tagged sql|postgres|postgresql|mysql|sqlite|bigquery.
 *   2. Line-anchored SELECT/INSERT/UPDATE/DELETE/CREATE/ALTER/DROP/WITH
 *      statements terminated by `;`.
 *
 * For each detected region, the lane tries to parse with node-sql-parser,
 * walks the AST, tokenises identifiers via the shared TokenVault (classifiers
 * `SQL_TABLE`, `SQL_SCHEMA`, optional `SQL_COLUMN`), then re-serialises.
 * Parse or serialise failure = silent pass-through, so a hostile or malformed
 * SQL snippet never corrupts the proxy request path.
 *
 * Integration contract: runs BEFORE regex + dictionary lanes in applyPolicy
 * because it performs structural rewrites whose length differs from the
 * original SQL. Regex/dict then scan the already-SQL-masked output, so their
 * offsets remain valid.
 */

import { Parser } from "node-sql-parser";
import type { DlpMatch } from "./dlp.js";
import type { TokenVault } from "./vault.js";

export interface SqlLaneConfig {
  enabled: boolean;
  includeColumns: boolean;
  dialect: "mysql" | "postgres" | "bigquery" | "sqlite";
}

export interface SqlLaneOptions {
  convId: string;
  vault: TokenVault;
}

export interface SqlLaneResult {
  output: string;
  matches: DlpMatch[];
}

interface SqlRegion {
  start: number;
  end: number;
}

// node-sql-parser's `database` option uses product-style names.
const DIALECT_MAP: Record<SqlLaneConfig["dialect"], string> = {
  mysql: "MySQL",
  postgres: "PostgresQL",
  bigquery: "BigQuery",
  sqlite: "SQLite",
};

// Matches the token shape issued by TokenVault (classifier upper + _NN / _NNN).
const PLACEHOLDER_TOKEN_RE = /^[A-Z][A-Z0-9_]*_\d{2,3}$/;

export class SqlLane {
  private readonly parser: Parser;
  private readonly config: SqlLaneConfig;
  private readonly dialect: string;

  constructor(config: SqlLaneConfig) {
    this.parser = new Parser();
    this.config = config;
    this.dialect = DIALECT_MAP[config.dialect];
  }

  apply(text: string, opts: SqlLaneOptions): SqlLaneResult {
    if (!this.config.enabled) return { output: text, matches: [] };
    if (!text || text.length === 0) return { output: text, matches: [] };
    const regions = detectSqlRegions(text);
    if (regions.length === 0) return { output: text, matches: [] };

    const matches: DlpMatch[] = [];
    // Process in reverse so earlier regions' offsets remain stable while we
    // splice later regions first.
    const descending = [...regions].sort((a, b) => b.start - a.start);
    let output = text;
    for (const r of descending) {
      const sql = output.slice(r.start, r.end);
      const masked = this.maskRegion(sql, opts, matches, r);
      if (masked !== sql) {
        output = output.slice(0, r.start) + masked + output.slice(r.end);
      }
    }
    return { output, matches };
  }

  private maskRegion(
    sql: string,
    opts: SqlLaneOptions,
    matches: DlpMatch[],
    region: SqlRegion,
  ): string {
    let ast: unknown;
    try {
      ast = this.parser.astify(sql, { database: this.dialect });
    } catch {
      return sql;
    }
    const hits: Hit[] = [];
    const astList = Array.isArray(ast) ? ast : [ast];
    for (const node of astList) this.walk(node, opts, hits);
    if (hits.length === 0) return sql;

    let newSql: string;
    try {
      // sqlify mutates column-case for some dialects; accept that as a known
      // visible difference — the semantic SQL remains equivalent.
      newSql = this.parser.sqlify(ast as never, { database: this.dialect });
    } catch {
      return sql;
    }

    for (const h of hits) {
      matches.push({
        patternName: `sql:${h.classifier.toLowerCase()}`,
        policy: "tokenize",
        start: region.start,
        end: region.end,
        sample: maskSample(h.original),
      });
    }
    return newSql;
  }

  private walk(node: unknown, opts: SqlLaneOptions, hits: Hit[], depth = 0): void {
    if (!node || typeof node !== "object" || depth > 32) return;
    const n = node as Record<string, unknown>;

    if (Array.isArray(n.from)) {
      for (const f of n.from) {
        this.tokenizeTableRef(f, opts, hits);
        // Recurse into the FROM entry so ON/JOIN sub-clauses (column_ref etc.)
        // get visited. tokenizeTableRef already handled table/db/expr.ast.
        if (f && typeof f === "object") {
          for (const k of Object.keys(f as Record<string, unknown>)) {
            if (k === "table" || k === "db" || k === "expr") continue;
            const v = (f as Record<string, unknown>)[k];
            if (!v || typeof v !== "object") continue;
            if (Array.isArray(v)) {
              for (const item of v) this.walk(item, opts, hits, depth + 1);
            } else {
              this.walk(v, opts, hits, depth + 1);
            }
          }
        }
      }
    }
    if (Array.isArray(n.table)) {
      for (const t of n.table) this.tokenizeTableRef(t, opts, hits);
    }
    // Column refs (e.g. `users.id` in ON/WHERE): always tokenise the table
    // qualifier so table names don't leak via ON clauses. The column itself is
    // gated by includeColumns.
    if (n.type === "column_ref") {
      this.tokenizeColumnRef(n, opts, hits);
    }

    for (const k of Object.keys(n)) {
      if (k === "from" || k === "table") continue;
      const v = n[k];
      if (!v || typeof v !== "object") continue;
      if (Array.isArray(v)) {
        for (const item of v) this.walk(item, opts, hits, depth + 1);
      } else {
        this.walk(v, opts, hits, depth + 1);
      }
    }
  }

  private tokenizeTableRef(ref: unknown, opts: SqlLaneOptions, hits: Hit[]): void {
    if (!ref || typeof ref !== "object") return;
    const r = ref as Record<string, unknown>;

    if (typeof r.table === "string" && !isPlaceholderToken(r.table)) {
      const tok = opts.vault.issue(opts.convId, "SQL_TABLE", r.table);
      hits.push({ classifier: "SQL_TABLE", original: r.table, token: tok });
      r.table = tok;
    }
    if (typeof r.db === "string" && !isPlaceholderToken(r.db)) {
      const tok = opts.vault.issue(opts.convId, "SQL_SCHEMA", r.db);
      hits.push({ classifier: "SQL_SCHEMA", original: r.db, token: tok });
      r.db = tok;
    }
    // Subquery table expression: { expr: { ast: Select }, as: ... }
    const expr = r.expr as { ast?: unknown } | undefined;
    if (expr && expr.ast) this.walk(expr.ast, opts, hits);
  }

  private tokenizeColumnRef(
    node: Record<string, unknown>,
    opts: SqlLaneOptions,
    hits: Hit[],
  ): void {
    // Table qualifier is always rewritten (vault dedup ensures consistency with
    // prior FROM/JOIN hits on the same name).
    if (typeof node.table === "string" && !isPlaceholderToken(node.table)) {
      const tok = opts.vault.issue(opts.convId, "SQL_TABLE", node.table);
      hits.push({ classifier: "SQL_TABLE", original: node.table, token: tok });
      node.table = tok;
    }
    // Column tokenisation is opt-in and skips generic identifiers.
    if (this.config.includeColumns) {
      const col = node.column;
      if (
        typeof col === "string" &&
        !isPlaceholderToken(col) &&
        !isGenericColumn(col)
      ) {
        const tok = opts.vault.issue(opts.convId, "SQL_COLUMN", col);
        hits.push({ classifier: "SQL_COLUMN", original: col, token: tok });
        node.column = tok;
      }
    }
  }
}

interface Hit {
  classifier: "SQL_TABLE" | "SQL_SCHEMA" | "SQL_COLUMN";
  original: string;
  token: string;
}

function isPlaceholderToken(s: string): boolean {
  return PLACEHOLDER_TOKEN_RE.test(s);
}

// Bare-bones allowlist of identifiers too generic to be worth tokenising
// (reserved for when includeColumns is enabled; still noisy without ALLOW_ALL
// stance, but better than tokenising `id` 50 times per session).
const GENERIC_COLUMN_NAMES = new Set<string>([
  "id",
  "name",
  "created_at",
  "updated_at",
  "deleted_at",
  "created",
  "updated",
  "type",
  "status",
]);
function isGenericColumn(s: string): boolean {
  return GENERIC_COLUMN_NAMES.has(s.toLowerCase());
}

function maskSample(s: string): string {
  if (s.length <= 4) return "*".repeat(s.length);
  return s.slice(0, 2) + "***" + s.slice(-1);
}

/**
 * Identify candidate SQL regions in `text`. Over-matching is tolerated — the
 * parser fallback downstream turns non-SQL hits into no-ops.
 */
export function detectSqlRegions(text: string): SqlRegion[] {
  const regions: SqlRegion[] = [];

  // (1) Fenced code block: ```sql\n...\n```
  const fenceRe =
    /```(sql|postgres|postgresql|mysql|sqlite|bigquery)[ \t]*\r?\n([\s\S]*?)\r?\n```/gi;
  let m: RegExpExecArray | null;
  while ((m = fenceRe.exec(text)) !== null) {
    const body = m[2];
    const bodyStart = m.index + m[0].indexOf(body, m[1].length);
    regions.push({ start: bodyStart, end: bodyStart + body.length });
  }

  // (2) Line-anchored statement terminated by ;
  const stmtRe =
    /(^|\n)[ \t]*(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|WITH)\b([\s\S]*?);/gi;
  while ((m = stmtRe.exec(text)) !== null) {
    const prefixLen = m[1].length;
    const start = m.index + prefixLen;
    const end = m.index + m[0].length;
    if (regions.some((r) => start >= r.start && end <= r.end)) continue;
    regions.push({ start, end });
  }

  return regions.sort((a, b) => a.start - b.start);
}
