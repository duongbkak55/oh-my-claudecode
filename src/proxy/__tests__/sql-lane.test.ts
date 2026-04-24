import { describe, it, expect } from "vitest";
import { SqlLane, detectSqlRegions } from "../sql-lane.js";
import { InProcessTokenVault } from "../vault.js";

function makeLane(
  overrides: Partial<{
    enabled: boolean;
    includeColumns: boolean;
    dialect: "mysql" | "postgres" | "bigquery" | "sqlite";
  }> = {},
) {
  return new SqlLane({
    enabled: overrides.enabled ?? true,
    includeColumns: overrides.includeColumns ?? false,
    dialect: overrides.dialect ?? "mysql",
  });
}

function makeVault() {
  const vault = new InProcessTokenVault();
  return { vault, convId: "conv-test" };
}

describe("SqlLane region detection", () => {
  it("detects a fenced sql code block", () => {
    const text = "before\n```sql\nSELECT * FROM users\n```\nafter";
    const regions = detectSqlRegions(text);
    expect(regions.length).toBe(1);
    expect(text.slice(regions[0]!.start, regions[0]!.end)).toBe(
      "SELECT * FROM users",
    );
  });

  it("detects line-anchored statement ending with semicolon", () => {
    const text = "SELECT * FROM orders;";
    const regions = detectSqlRegions(text);
    expect(regions.length).toBe(1);
    expect(regions[0]!.start).toBe(0);
    expect(regions[0]!.end).toBe(text.length);
  });

  it("does NOT match SQL verbs mid-sentence (prose safety)", () => {
    const text = "Please UPDATE your profile before DELETE the file";
    const regions = detectSqlRegions(text);
    expect(regions.length).toBe(0);
  });

  it("does NOT match statement without trailing semicolon outside fence", () => {
    const text = "I want to SELECT * FROM users but never ran it";
    const regions = detectSqlRegions(text);
    // no `;` so line-anchored rule rejects; no fence so fence rule rejects.
    expect(regions.length).toBe(0);
  });

  it("does not double-report a statement already inside a fenced region", () => {
    const text = "```sql\nSELECT * FROM orders;\n```";
    const regions = detectSqlRegions(text);
    expect(regions.length).toBe(1);
    expect(text.slice(regions[0]!.start, regions[0]!.end).trim()).toBe(
      "SELECT * FROM orders;",
    );
  });

  it("finds multiple regions in the same prompt", () => {
    const text =
      "First: ```sql\nSELECT * FROM a\n``` then inline:\nDELETE FROM b;";
    const regions = detectSqlRegions(text);
    expect(regions.length).toBe(2);
  });
});

describe("SqlLane masking", () => {
  it("tokenises a simple table name in a fenced block", () => {
    const lane = makeLane();
    const vault = makeVault();
    const input = "```sql\nSELECT * FROM customers\n```";
    const r = lane.apply(input, vault);
    expect(r.output).not.toEqual(input);
    expect(r.output).toContain("SQL_TABLE_01");
    expect(r.output).not.toContain("customers");
    expect(r.matches.length).toBe(1);
    expect(r.matches[0]!.patternName).toBe("sql:sql_table");
    expect(vault.vault.lookup(vault.convId, "SQL_TABLE_01")).toBe("customers");
  });

  it("tokenises multiple tables in a JOIN", () => {
    const lane = makeLane();
    const vault = makeVault();
    const input = "SELECT a.id FROM users a JOIN orders b ON a.id = b.user_id;";
    const r = lane.apply(input, vault);
    expect(r.output).toContain("SQL_TABLE_01");
    expect(r.output).toContain("SQL_TABLE_02");
    expect(r.output).not.toContain("users");
    expect(r.output).not.toContain("orders");
    // Table hits from FROM/JOIN recorded for audit (distinct table names only:
    // 2 FROM entries; ON-clause references share vault tokens so no duplicate
    // vault entries, but each qualifier encounter is reported once.).
    const tableMatches = r.matches.filter(
      (m) => m.patternName === "sql:sql_table",
    );
    expect(tableMatches.length).toBeGreaterThanOrEqual(2);
  });

  it("does NOT leak table names via ON-clause column qualifiers (e.g. users.id)", () => {
    const lane = makeLane();
    const vault = makeVault();
    const input =
      "SELECT * FROM users JOIN orders ON users.id = orders.user_id;";
    const r = lane.apply(input, vault);
    // Raw names must not appear anywhere in the output, including in ON.
    expect(r.output).not.toContain("users");
    expect(r.output).not.toContain("orders");
    // Column names (id, user_id) should still be present because
    // includeColumns=false.
    expect(r.output).toContain("id");
  });

  it("tokenises a schema-qualified table as separate SCHEMA + TABLE", () => {
    const lane = makeLane();
    const vault = makeVault();
    const input = "SELECT * FROM my_schema.orders;";
    const r = lane.apply(input, vault);
    // MySQL dialect wraps identifiers in backticks; accept either form.
    expect(r.output).toMatch(/`?SQL_SCHEMA_01`?\.`?SQL_TABLE_01`?/);
    expect(vault.vault.lookup(vault.convId, "SQL_SCHEMA_01")).toBe("my_schema");
    expect(vault.vault.lookup(vault.convId, "SQL_TABLE_01")).toBe("orders");
  });

  it("deduplicates: same table appearing twice gets one token", () => {
    const lane = makeLane();
    const vault = makeVault();
    const input =
      "SELECT * FROM users WHERE id IN (SELECT id FROM users WHERE active = 1);";
    const r = lane.apply(input, vault);
    // Only one distinct SQL_TABLE_NN token should exist for 'users'.
    expect(r.output.match(/SQL_TABLE_\d+/g)?.length).toBeGreaterThan(0);
    expect(vault.vault.lookup(vault.convId, "SQL_TABLE_01")).toBe("users");
    // SQL_TABLE_02 should NOT exist because dedup works per-classifier per-conv.
    expect(vault.vault.lookup(vault.convId, "SQL_TABLE_02")).toBeNull();
  });

  it("does not tokenise columns when includeColumns=false (default)", () => {
    const lane = makeLane();
    const vault = makeVault();
    const input = "SELECT customer_name FROM users;";
    const r = lane.apply(input, vault);
    expect(r.output).toContain("SQL_TABLE_01");
    expect(r.output).toContain("customer_name"); // not tokenised
    expect(r.matches.filter((m) => m.patternName === "sql:sql_column").length).toBe(
      0,
    );
  });

  it("tokenises columns when includeColumns=true (skipping generics)", () => {
    const lane = makeLane({ includeColumns: true });
    const vault = makeVault();
    const input = "SELECT customer_name, id FROM users;";
    const r = lane.apply(input, vault);
    // customer_name tokenised; id (generic) is not.
    expect(vault.vault.lookup(vault.convId, "SQL_COLUMN_01")).toBe(
      "customer_name",
    );
    expect(r.output).toContain("id"); // preserved
    expect(r.output).not.toContain("customer_name");
  });

  it("passes through malformed SQL without corrupting text", () => {
    const lane = makeLane();
    const vault = makeVault();
    const input = "```sql\nSELCT *** WHERE FROM\n```";
    const r = lane.apply(input, vault);
    expect(r.output).toBe(input);
    expect(r.matches.length).toBe(0);
  });

  it("does nothing when enabled=false", () => {
    const lane = makeLane({ enabled: false });
    const vault = makeVault();
    const input = "SELECT * FROM users;";
    const r = lane.apply(input, vault);
    expect(r.output).toBe(input);
    expect(r.matches.length).toBe(0);
  });

  it("leaves non-SQL text untouched", () => {
    const lane = makeLane();
    const vault = makeVault();
    const input = "Please help me refactor this function: function foo() {}";
    const r = lane.apply(input, vault);
    expect(r.output).toBe(input);
    expect(r.matches.length).toBe(0);
  });

  it("supports round-trip: masked output can be detokenised back to original SQL", () => {
    const lane = makeLane();
    const vault = makeVault();
    const input = "SELECT * FROM customers;";
    const r = lane.apply(input, vault);
    // Detokenise by lookup
    const masked = r.output;
    const tok = vault.vault.listTokensForConv(vault.convId)[0]!;
    const original = vault.vault.lookup(vault.convId, tok)!;
    const restored = masked.replace(tok, original);
    // parser.sqlify may re-case keywords and quote identifiers with backticks
    // (MySQL dialect default). Canonicalise by lowercasing, stripping
    // backticks, collapsing whitespace, and trimming trailing semicolon.
    const canon = (s: string) =>
      s.toLowerCase().replace(/`/g, "").replace(/\s+/g, " ").replace(/;$/, "").trim();
    expect(canon(restored)).toBe(canon(input));
  });

  it("does not crash on empty input", () => {
    const lane = makeLane();
    const vault = makeVault();
    const r = lane.apply("", vault);
    expect(r.output).toBe("");
    expect(r.matches.length).toBe(0);
  });

  it("ignores a non-SQL fenced block (e.g. ```python)", () => {
    const lane = makeLane();
    const vault = makeVault();
    const input = "```python\nSELECT_ALL = True\n```";
    const r = lane.apply(input, vault);
    expect(r.output).toBe(input);
    expect(r.matches.length).toBe(0);
  });
});
