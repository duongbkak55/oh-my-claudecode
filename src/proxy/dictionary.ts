/**
 * Dictionary matcher for internal source-code identifiers — package names,
 * codenames, partner names, internal hostnames. Backed by an Aho-Corasick
 * automaton so thousands of entries can be scanned in one O(n + matches) pass
 * over the text.
 *
 * Design:
 *  - NFC-normalize both inputs and terms so typographical equivalents match.
 *  - INTERNAL_PACKAGE is case-sensitive (package names care about case in
 *    most ecosystems). Other classes are case-insensitive; for those we
 *    scan the lower-cased text and keep the original term for reporting.
 *  - Word-boundary check on both ends prevents "Vietcombank" from matching
 *    inside "Vietcombanking". Boundaries are ASCII-ish; we accept alnum
 *    [A-Za-z0-9_] as a "word char", which fits package names and codenames.
 *    We also treat `@`, `/`, `-`, `.` as valid interior characters inside a
 *    term and let the automaton's literal match handle that — boundaries are
 *    only enforced at the exterior of each match.
 *  - Non-overlapping + longest-leftmost-wins: we emit matches in order of
 *    start index; when two overlap we keep the one that started earlier,
 *    breaking ties by longest end offset.
 *
 * No external dependency — ~180 LOC of TypeScript.
 */

export interface DictionaryEntry {
  term: string;
  classifier: string;
  policy: "block" | "redact" | "tokenize";
  tenantId?: string;
}

export interface DictionaryMatch {
  start: number;
  end: number;
  classifier: string;
  policy: "block" | "redact" | "tokenize";
  term: string;
}

interface Node {
  next: Map<number, number>;
  fail: number;
  outputs: number[];
}

interface CompiledTerm {
  term: string;
  normalized: string;
  classifier: string;
  policy: "block" | "redact" | "tokenize";
  caseInsensitive: boolean;
  length: number;
}

const CASE_SENSITIVE_CLASSES = new Set<string>(["INTERNAL_PACKAGE"]);

function isWordChar(ch: string | undefined): boolean {
  if (!ch) return false;
  return /^[A-Za-z0-9_]$/.test(ch);
}

function normalize(s: string): string {
  return s.normalize("NFC");
}

export class Dictionary {
  private nodesCS: Node[] = [];
  private nodesCI: Node[] = [];
  private termsCS: CompiledTerm[] = [];
  private termsCI: CompiledTerm[] = [];
  private hasCS = false;
  private hasCI = false;

  constructor(entries: DictionaryEntry[]) {
    this.reload(entries);
  }

  reload(entries: DictionaryEntry[]): void {
    this.termsCS = [];
    this.termsCI = [];
    for (const e of entries) {
      const cls = e.classifier.toUpperCase();
      const caseInsensitive = !CASE_SENSITIVE_CLASSES.has(cls);
      const norm = normalize(e.term);
      const final = caseInsensitive ? norm.toLowerCase() : norm;
      const ct: CompiledTerm = {
        term: e.term,
        normalized: final,
        classifier: cls,
        policy: e.policy,
        caseInsensitive,
        length: final.length,
      };
      if (caseInsensitive) this.termsCI.push(ct);
      else this.termsCS.push(ct);
    }
    this.hasCS = this.termsCS.length > 0;
    this.hasCI = this.termsCI.length > 0;
    this.nodesCS = this.hasCS ? buildAutomaton(this.termsCS) : [];
    this.nodesCI = this.hasCI ? buildAutomaton(this.termsCI) : [];
  }

  scan(text: string): DictionaryMatch[] {
    if (!text) return [];
    const normalized = normalize(text);
    const results: DictionaryMatch[] = [];
    if (this.hasCS) {
      runAutomaton(normalized, normalized, this.nodesCS, this.termsCS, results);
    }
    if (this.hasCI) {
      const lower = normalized.toLowerCase();
      runAutomaton(normalized, lower, this.nodesCI, this.termsCI, results);
    }
    return dedupeLongestLeftmost(results);
  }
}

function buildAutomaton(terms: CompiledTerm[]): Node[] {
  const nodes: Node[] = [{ next: new Map(), fail: 0, outputs: [] }];
  // Insert terms.
  for (let i = 0; i < terms.length; i++) {
    const t = terms[i]!;
    let cur = 0;
    for (let j = 0; j < t.normalized.length; j++) {
      const code = t.normalized.charCodeAt(j);
      let nxt = nodes[cur]!.next.get(code);
      if (nxt === undefined) {
        nxt = nodes.length;
        nodes.push({ next: new Map(), fail: 0, outputs: [] });
        nodes[cur]!.next.set(code, nxt);
      }
      cur = nxt;
    }
    nodes[cur]!.outputs.push(i);
  }
  // BFS for failure links.
  const queue: number[] = [];
  for (const [, child] of nodes[0]!.next) {
    nodes[child]!.fail = 0;
    queue.push(child);
  }
  while (queue.length > 0) {
    const u = queue.shift()!;
    const uNode = nodes[u]!;
    for (const [code, v] of uNode.next) {
      queue.push(v);
      let f = uNode.fail;
      while (f !== 0 && !nodes[f]!.next.has(code)) {
        f = nodes[f]!.fail;
      }
      const candidate = nodes[f]!.next.get(code);
      nodes[v]!.fail =
        candidate !== undefined && candidate !== v ? candidate : 0;
      for (const out of nodes[nodes[v]!.fail]!.outputs) {
        nodes[v]!.outputs.push(out);
      }
    }
  }
  return nodes;
}

function runAutomaton(
  original: string,
  scanText: string,
  nodes: Node[],
  terms: CompiledTerm[],
  sink: DictionaryMatch[],
): void {
  let state = 0;
  for (let i = 0; i < scanText.length; i++) {
    const code = scanText.charCodeAt(i);
    while (state !== 0 && !nodes[state]!.next.has(code)) {
      state = nodes[state]!.fail;
    }
    const nxt = nodes[state]!.next.get(code);
    state = nxt !== undefined ? nxt : 0;
    if (nodes[state]!.outputs.length === 0) continue;
    for (const outIdx of nodes[state]!.outputs) {
      const t = terms[outIdx]!;
      const end = i + 1;
      const start = end - t.length;
      if (start < 0) continue;
      const before = original[start - 1];
      const after = original[end];
      if (isWordChar(before)) continue;
      if (isWordChar(after)) continue;
      sink.push({
        start,
        end,
        classifier: t.classifier,
        policy: t.policy,
        term: t.term,
      });
    }
  }
}

function dedupeLongestLeftmost(matches: DictionaryMatch[]): DictionaryMatch[] {
  if (matches.length <= 1) return matches.slice();
  const sorted = matches.slice().sort((a, b) => {
    if (a.start !== b.start) return a.start - b.start;
    return b.end - a.end;
  });
  const out: DictionaryMatch[] = [];
  let cursor = -1;
  for (const m of sorted) {
    if (m.start < cursor) continue;
    out.push(m);
    cursor = m.end;
  }
  return out;
}
