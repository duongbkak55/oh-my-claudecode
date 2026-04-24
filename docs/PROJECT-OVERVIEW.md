# oh-my-claudecode (OMC) — Comprehensive Feature Catalogue

> Version documented: **4.9.3** (npm package `oh-my-claude-sisyphus`)
> Upstream repo: [Yeachan-Heo/oh-my-claudecode](https://github.com/Yeachan-Heo/oh-my-claudecode)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [High-Level Architecture](#2-high-level-architecture)
3. [Installation and Setup](#3-installation-and-setup)
4. [Orchestration Modes](#4-orchestration-modes)
5. [Skill Catalogue](#5-skill-catalogue)
6. [Agent Catalogue](#6-agent-catalogue)
7. [Commands and CLI](#7-commands-and-cli)
8. [Hooks and Event Taxonomy](#8-hooks-and-event-taxonomy)
9. [MCP Servers and Integrations](#9-mcp-servers-and-integrations)
10. [State and Memory Model](#10-state-and-memory-model)
11. [Tier and Delegation Model](#11-tier-and-delegation-model)
12. [Execution Modes Deep-Dive](#12-execution-modes-deep-dive)
13. [Performance and Observability](#13-performance-and-observability)
14. [AI Egress Proxy](#14-ai-egress-proxy)
15. [Agent Team Pipeline](#15-agent-team-pipeline)
16. [Compatibility and Migration](#16-compatibility-and-migration)
17. [Testing, Build, and Release Pipeline](#17-testing-build-and-release-pipeline)
18. [Not in This Repo](#18-not-in-this-repo)
19. [Where to Go Next](#19-where-to-go-next)
20. [Document Provenance](#20-document-provenance)

---

## 1. Executive Summary

oh-my-claudecode (OMC) is a multi-agent orchestration layer that plugs into Claude Code CLI and extends it with specialized agents, workflow skills, persistent state, notification routing, and an optional AI egress proxy. The engineer installs it once — via the Claude Code plugin marketplace, npm, or a local development checkout — and from that point Claude Code sessions gain automatic keyword detection, agent delegation, and cross-session memory with no changes to existing prompts or workflows.

**What you get:**

- A catalogue of 19 specialized agents (haiku / sonnet / opus tiers) that Claude can delegate to for execution, architecture, review, QA, writing, and research work.
- ~32 workflow skills covering persistence loops (ralph), maximum parallelism (ultrawork), full autonomous pipelines (autopilot), consensus planning (ralplan), tri-model orchestration (ccg), and many more.
- Persistent state and memory (notepad, project memory, session-scoped files) that survives context compaction and cross-session breaks.
- An `omc` CLI with ~18 named subcommands covering setup, team management, session search, worktree teleport, rate-limit waiting, notification configuration, and a HUD statusline renderer.
- An in-process AI egress proxy (`src/proxy/`) that intercepts outbound Anthropic API traffic, runs multi-lane DLP (regex, Aho-Corasick dictionary, SQL-AST, tree-sitter AST), tokenises PII and source-code identifiers into opaque vault tokens, and detokenises them in the inbound SSE stream — preventing accidental egress of personal data and proprietary code.

**What it is not:** OMC is not a replacement for Claude Code, not a new language model, not a self-hosted server you must run, and not an independent product. It is a plugin and orchestration layer that rides on top of Claude Code's existing hook, agent, and MCP infrastructure.

---

## 2. High-Level Architecture

OMC is built on four interlocking systems that the canonical `docs/ARCHITECTURE.md` describes in full. The layers, from lowest to highest level of abstraction:

```
┌──────────────────────────────────────────────────────────┐
│  User Input / Claude Code CLI (claude command)            │
└──────────────────────────────────┬───────────────────────┘
                                   │  hook events
                                   ▼
┌──────────────────────────────────────────────────────────┐
│  HOOKS  (hooks/hooks.json + scripts/*.mjs)                │
│  11 lifecycle events — keyword detection, skill inject,   │
│  pre-tool enforcement, session start/end, compaction      │
└──────────────────────────────────┬───────────────────────┘
                                   │  system-reminder injection
                                   ▼
┌──────────────────────────────────────────────────────────┐
│  SKILLS  (skills/*/SKILL.md)                              │
│  ~32 workflow skills — autopilot, ralph, ultrawork,       │
│  team, ccg, ralplan, trace, omc-plan, and more            │
└──────────────────────────────────┬───────────────────────┘
                                   │  Task tool delegation
                                   ▼
┌──────────────────────────────────────────────────────────┐
│  AGENTS  (agents/*.md + src/agents/)                      │
│  19 named roles across 4 lanes, mapped to haiku/sonnet/   │
│  opus by default; delegation-enforcer auto-injects model  │
└──────────────────────────────────┬───────────────────────┘
                                   │  read/write
                                   ▼
┌──────────────────────────────────────────────────────────┐
│  STATE  (.omc/ + ~/.omc/)                                 │
│  notepad.md, project-memory.json, plans/, sessions/,      │
│  logs/, per-mode JSON state files                         │
└──────────────────────────────────────────────────────────┘

  Orthogonal layers:
  ┌─────────────────────────────────────────────────────────┐
  │  MCP SERVERS  (bridge/mcp-server.cjs, team-bridge.cjs,  │
  │  team-mcp.cjs)  —  state tools, notepad tools, team     │
  │  API, LSP/AST tools exposed as MCP tool calls           │
  └─────────────────────────────────────────────────────────┘
  ┌─────────────────────────────────────────────────────────┐
  │  CLI  (bridge/cli.cjs = omc binary)                      │
  │  ~18 subcommands: setup, team, wait, teleport, ask, hud  │
  └─────────────────────────────────────────────────────────┘
  ┌─────────────────────────────────────────────────────────┐
  │  PROXY  (src/proxy/)  —  HTTP proxy between Claude Code  │
  │  and api.anthropic.com; DLP + vault + audit log          │
  └─────────────────────────────────────────────────────────┘
  ┌─────────────────────────────────────────────────────────┐
  │  OPENCLAW BRIDGE  (src/openclaw/)  —  normalised signal  │
  │  routing to Telegram / Discord / Slack / webhooks        │
  └─────────────────────────────────────────────────────────┘
```

The canonical architecture reference is `docs/ARCHITECTURE.md`. The present document cross-links to it throughout rather than duplicating the diagrams it contains.

---

## 3. Installation and Setup

### Primary install paths

**Plugin marketplace (recommended for most users):**

```bash
# Inside Claude Code:
/plugin marketplace add https://github.com/Yeachan-Heo/oh-my-claudecode
/plugin install oh-my-claudecode

# Then run the setup skill to sync CLAUDE.md, hooks, and agents:
/oh-my-claudecode:omc-setup
```

**npm global package:**

```bash
npm i -g oh-my-claude-sisyphus@latest
omc setup
```

The npm package name `oh-my-claude-sisyphus` is the stable publish name kept for backward compatibility from before the 3.0 rebrand; the plugin name and all slash-command prefixes use `oh-my-claudecode`.

**Local development checkout:**
Follow `docs/LOCAL_PLUGIN_INSTALL.md`. The key steps are:

```bash
claude plugin marketplace add /path/to/oh-my-claudecode
claude plugin install oh-my-claudecode@oh-my-claudecode
# Inside Claude Code:
/setup
```

The local install is worktree-aware: each worktree gets its own plugin registration and can run a different branch of OMC simultaneously.

### Post-install verification

```bash
omc doctor conflicts   # CLI check for plugin coexistence issues
/oh-my-claudecode:omc-doctor   # In-session diagnostic skill
```

The `omc-doctor` skill (`skills/omc-doctor/SKILL.md`) checks installed vs. latest version, hook registration, MCP server status, and config file locations.

### Key environment variables

| Variable | Purpose |
|---|---|
| `ANTHROPIC_API_KEY` | Required for Claude Code and the egress proxy |
| `OMC_PROXY_CLIENT_TOKEN` | Bearer token for the AI egress proxy |
| `OMC_PROXY_SQL_DLP` | `1` to enable SQL-AST DLP lane in proxy |
| `OMC_PROXY_AST_DLP` | `1` to enable tree-sitter AST DLP lane in proxy |
| `OMC_STATE_DIR` | Override project-local state to a central path (see §10) |
| `OMC_NOTIFY_PROFILE` | Active notification profile name |
| `DISABLE_OMC` | Set to any value to disable all OMC hooks |
| `OMC_SKIP_HOOKS` | Comma-separated hook names to skip selectively |
| `OMC_DEBUG` | `true` to enable verbose delegation-enforcer logging |
| `OMC_NOTIFY` | `0` to suppress all stop/session notifications |
| `CLAUDE_CONFIG_DIR` | Override `~/.claude` base; respected by all OMC path logic |

---

## 4. Orchestration Modes

OMC provides a set of named orchestration modes. Each is implemented as a skill and can be triggered by keyword detection or explicit slash command. The modes compose: ralph wraps ultrawork, autopilot incorporates ralph (which incorporates ultrawork). The mode that best fits a task depends on the desired level of autonomy, the need for persistence guarantees, and whether parallel execution is needed.

### Team

**What it does:** Spawns N coordinated Claude Code agent processes working from a shared task list, managed through Claude Code's native team infrastructure. Follows the canonical five-stage pipeline: `team-plan → team-prd → team-exec → team-verify → team-fix`. Each worker claims tasks atomically, preventing duplicate work.

**Trigger:** `/oh-my-claudecode:team N:agent-type "task"` — explicit invocation, not keyword-detected by default.

**When to reach for it:** Any multi-component task where independent subtasks exist and benefit from true process-level parallelism. This is the primary parallel execution surface in OMC; the documentation recommends preferring team over ad-hoc ultrawork when the overhead is proportionate.

**Skill file:** `skills/team/SKILL.md`

### Autopilot

**What it does:** Full autonomous five-phase pipeline from a two-to-three line idea to verified, working code. Phases: expansion (analyst + architect expand requirements), planning (architect creates execution plan, critic validates), execution (ralph + ultrawork implement), QA (ultraqa cycle: test-fix-repeat), validation (three independent validators: functional, security, quality).

**Triggers:** `autopilot`, `build me`, `I want a`, `create me`, `make me`, `full auto`, `handle it all`, `I want a/an...`

**When to reach for it:** When the user can describe what they want in a few sentences and wants fully hands-off execution through to a verified outcome. Autopilot is the highest-level orchestration mode; it internally spawns ralph, ultrawork, and ultraqa.

**Skill file:** `skills/autopilot/SKILL.md`

### Ralph

**What it does:** A PRD-driven persistence loop. Ralph writes a `.omc/plans/prd-*.md` and a `test-spec-*.md`, then iterates — using ultrawork for parallel execution — until every user story in the PRD has `passes: true` and the verifier agent has signed off. The loop is bounded by a configurable max-iterations count. A stop hook enforces the "boulder never stops" invariant: when ralph is active, Claude cannot stop until verification passes.

**Triggers:** `ralph`, `don't stop`, `must complete`, `finish this`, `keep going until done`

**When to reach for it:** When the task absolutely must complete and partial progress is unacceptable. Ralph is appropriate for critical migrations, security fixes, or anything where "do your best" is not enough. Note that ralph is significantly heavier than ultrawork alone: it includes PRD generation, per-iteration state writes, and mandatory verifier sign-off.

**Gotcha:** Ralph enforces a planning gate — it will not begin implementation until both the PRD and test-spec artifacts exist in `.omc/plans/`. If they are missing, ralph stays in planning phase.

**Skill file:** `skills/ralph/SKILL.md`

### Ultrawork

**What it does:** Parallel execution engine. Launches multiple agents simultaneously for independent subtasks. Provides parallelism and smart model routing but does not provide persistence, verification loops, or state management on its own. It is a component (execution substrate) rather than a standalone guarantee.

**Triggers:** `ultrawork`, `ulw`, `uw`

**When to reach for it:** When multiple independent tasks can run simultaneously and the user is comfortable managing completion. For guaranteed completion, use ralph (which includes ultrawork). For a full autonomous pipeline, use autopilot (which includes ralph which includes ultrawork).

**Skill file:** `skills/ultrawork/SKILL.md`

### Ralplan

**What it does:** Consensus planning entrypoint. Runs an iterative loop among planner, architect, and critic agents until they reach consensus on a plan. Supports two modes: short (default, faster) and deliberate (for high-risk work: adds pre-mortem scenarios and expanded test planning). Ralplan auto-enables deliberate mode when the request explicitly signals high risk (auth/security, migrations, destructive changes, production incidents, PII, public API breakage).

**Triggers:** `ralplan`, `consensus plan`

**When to reach for it:** Before any ralph or autopilot run on work that is architecturally complex, risky, or ambiguous. The ralplan-first gate is enforced automatically when ralph is active and planning is incomplete.

**Flags:** `--interactive` (prompts user at key steps), `--deliberate` (forces deliberate mode)

**Skill file:** `skills/ralplan/SKILL.md`

### Pipeline (legacy / partial)

**What it does:** Sequential agent chaining with data passing between stages. For example: `explore:haiku → architect:opus → executor:sonnet`. Provides built-in presets: `review`, `implement`, `debug`, `research`, `refactor`, `security`.

**Status:** Introduced in v3.4.0. The unified `/cancel` command supports cancelling active pipeline runs. The pipeline mode is less commonly used now that the team mode provides more robust coordination.

**Skill file:** Not a standalone skill; pipeline is invoked via the plan skill's `--pipeline` flag or directly.

### Swarm (deprecated)

**What it was:** The legacy parallel coordination mode from pre-3.5 that used SQLite-based task tracking. Replaced by the native team mode (Claude Code built-in team infrastructure, no external dependencies). The `swarm` compatibility alias was removed in PR #1131. The replacement is `/oh-my-claudecode:team`.

### Ultrapilot (deprecated)

**What it was:** A legacy "parallel autopilot" variant from v3.4. Replaced by autopilot, which now internally uses ralph + ultrawork for the same effect. If you encounter `/oh-my-claudecode:ultrapilot` in older scripts, replace with `/oh-my-claudecode:autopilot`.

### CCG (Claude-Codex-Gemini)

**What it does:** Routes a prompt to Codex (via `omc ask codex`) and Gemini (via `omc ask gemini`) in parallel, then Claude synthesises both outputs into one answer. This provides multi-model cross-validation without launching tmux team workers.

**Triggers:** `ccg`, `claude-codex-gemini`

**When to reach for it:** Code review from multiple AI perspectives simultaneously; cross-validation where the two external models may disagree; advisor-style fast parallel input without the overhead of a full team session.

**Skill file:** `skills/ccg/SKILL.md`

### omc-teams (tmux CLI workers)

**What it does:** Spawns N CLI worker processes in tmux panes. Supports three agent types: `claude`, `codex`, and `gemini`. This is a legacy compatibility skill for the CLI-first runtime path.

**Trigger:** `/oh-my-claudecode:omc-teams N:claude|codex|gemini "task"`

**Status:** The MCP-based team runtime tools (`omc_run_team_start`, `omc_run_team_status`, etc.) are hard-deprecated and return a `deprecated_cli_only` error. Use `omc team` CLI commands instead. The `/omc-teams` skill itself remains as a compatibility entrypoint.

**Skill file:** `skills/omc-teams/SKILL.md`

### Ultraqa

**What it does:** Autonomous QA cycling. Runs the loop `qa-tester → architect verification → fix → repeat` until the stated quality goal is met.

**Trigger:** `/oh-my-claudecode:ultraqa [goal]`

**When to reach for it:** After implementation is complete and the user wants test/fix cycles automated. Autopilot calls ultraqa internally in its QA phase; ultraqa can also be invoked standalone.

**Skill file:** `skills/ultraqa/SKILL.md`

### Ralphthon

**What it does:** An autonomous hackathon lifecycle: deep-interview generates the PRD, ralph loop executes tasks, an auto-hardening phase runs, and the workflow terminates after clean verification waves. Available as both a CLI command (`omc ralphthon`) and internally structured as a multi-phase orchestrator.

**Trigger:** `omc ralphthon [args...]`

**When to reach for it:** Hackathon-style "start from scratch and ship something" sessions where a full idea-to-shipped cycle is needed with minimal human checkpoints.

**CLI file:** `src/cli/commands/ralphthon.ts`

---

## 5. Skill Catalogue

Skills are workflow behaviour-injections invoked via `/oh-my-claudecode:<name>` or via magic keyword detection. Each skill lives in `skills/<name>/SKILL.md`. The file's YAML frontmatter declares the name, description, level, triggers, and optional pipeline links.

Skill levels are informal complexity ratings (1 = trivial utility, 7 = self-improving meta-skill). The `user-invocable: false` frontmatter flag marks internal skills that should not be called directly.

### Workflow Skills

These skills drive multi-phase execution pipelines.

| Skill | Trigger keyword(s) | One-line purpose |
|---|---|---|
| `autopilot` | `autopilot`, `build me`, `I want a` | Full autonomous 5-phase pipeline: expansion → planning → execution → QA → validation |
| `ralph` | `ralph`, `don't stop`, `must complete` | PRD-driven persistence loop; will not stop until verifier signs off |
| `ultrawork` | `ulw`, `ultrawork`, `uw` | Parallel execution engine; launches multiple agents simultaneously |
| `team` | explicit `/team` invocation | N coordinated agents on shared task list, 5-stage team pipeline |
| `ralplan` | `ralplan`, `consensus plan` | Iterative planner → architect → critic consensus loop before execution |
| `ultraqa` | `/ultraqa [goal]` | Autonomous QA cycling: test → verify → fix → repeat |
| `omc-plan` (plan) | `plan this`, `let's plan` | Strategic planning with optional interview workflow; feeds autopilot |
| `deep-interview` | `deep interview`, `ouroboros`, `interview me` | Socratic ambiguity-scored interview (Ouroboros-style); gates on <20% ambiguity before proceeding |
| `deep-dive` | `deep dive`, `investigate deeply` | 2-stage pipeline: trace → deep-interview → omc-plan → autopilot |
| `ccg` | `ccg`, `claude-codex-gemini` | Tri-model: Codex + Gemini in parallel, Claude synthesises |
| `sciomc` | `/sciomc <goal>` | Parallel scientist-agent research orchestration with AUTO mode |
| `external-context` | `/external-context <topic>` | Parallel document-specialist web/doc research across 2–5 facets |
| `ai-slop-cleaner` | `deslop`, `anti-slop`, `AI slop` | Regression-safe cleanup of bloated/duplicate AI-generated code |
| `visual-verdict` | `/visual-verdict` | Structured JSON pass/fail verdict for screenshot-to-reference comparisons |
| `omc-teams` | `/omc-teams N:type "task"` | tmux CLI worker spawner (legacy compatibility, see §4) |

### Utility Skills

These skills configure, introspect, or provide narrow single-purpose capabilities.

| Skill | Trigger / Invocation | One-line purpose |
|---|---|---|
| `cancel` | `/cancel`, `stop`, `abort`, `cancelomc` | Auto-detects active mode and cancels it cleanly |
| `omc-setup` | `/omc-setup`, "setup omc" | Install/refresh OMC from plugin, npm, or local-dev source |
| `setup` | `/setup` | Unified setup entrypoint; routes to omc-setup, doctor, or mcp-setup |
| `omc-doctor` | `/omc-doctor` | Diagnose installation version, hook registration, and config issues |
| `omc-reference` | auto-loaded | Internal agent/tools/pipeline reference; not user-invocable directly |
| `hud` | `/hud [setup\|preset]` | Configure HUD statusline display options and layout presets |
| `mcp-setup` | `/mcp-setup` | Interactive wizard to configure popular MCP servers (filesystem, web, GitHub, exa) |
| `skill` | `/skill list\|add\|remove\|search\|edit` | Manage local skills (list, add, remove, search, edit) |
| `learner` | `/learner` | Extract a reusable skill from the current conversation and save it |
| `note` | `/note <content>` | Save a note to the session notepad |
| `trace` | `/trace` | Evidence-driven tracing lane: parallel competing-hypothesis causal investigation |
| `release` | `/release <version\|patch\|minor>` | Automated release workflow for OMC itself |
| `deepinit` | `/deepinit [path]` | Generate hierarchical AGENTS.md documentation across the codebase |
| `configure-notifications` | `/configure-notifications`, "configure telegram" | Configure Telegram / Discord / Slack notification integrations |
| `writer-memory` | `/writer-memory init\|char\|rel\|scene\|query\|...` | Agentic persistent memory for fiction writers; tracks characters, world, scenes, themes |
| `project-session-manager` | `/project-session-manager`, `psm` | Worktree-first dev environment manager: issues, PRs, features, tmux sessions |
| `ralph-init` | `/ralph-init "idea"` | Initialise a ralph session with PRD and user stories before the loop starts |
| `ask` | `/ask <claude\|codex\|gemini> <question>` | Route a prompt through a provider CLI and write an ask artifact |

### Planning Skills

| Skill | Invocation | One-line purpose |
|---|---|---|
| `omc-plan` | `/omc-plan [--consensus] [--review]` | Strategic planning with optional RALPLAN-DR consensus mode |
| `ralplan` | `/ralplan [--deliberate] [--interactive]` | Alias for omc-plan --consensus with configurable deliberation depth |
| `deep-dive` | `/deep-dive <target>` | Trace → interview pipeline producing a spec artifact |
| `deepinit` | `/deepinit [path]` | Hierarchical AGENTS.md generation for AI-readable codebase docs |
| `deep-interview` | `/deep-interview [--quick\|--standard\|--deep]` | Socratic interview with mathematical ambiguity scoring |

---

## 6. Agent Catalogue

Agents are specialised sub-agents invoked through Claude Code's `Task` tool with the prefix `oh-my-claudecode:<name>`. Each agent has its own markdown prompt in `agents/<name>.md`, a default model tier, and clear role boundaries. The canonical reference is `docs/ARCHITECTURE.md` §Agent System.

Nineteen agents are shipped in `agents/`. The AGENTS.md file at the repo root (and mirrored at `docs/AGENTS.md`) contains the condensed catalogue used by the orchestrator at runtime.

### Build / Analysis Lane

These agents cover the full development lifecycle from exploration to delivery.

| Agent | Default model | Role |
|---|---|---|
| `explore` | haiku | Fast codebase discovery: file/symbol mapping, pattern search. Read-only; uses parallel tool calls. |
| `analyst` | opus | Requirements clarity, acceptance criteria extraction, hidden constraint discovery |
| `planner` | opus | Task sequencing, execution plan creation, risk identification |
| `architect` | opus | System design, interface definition, long-horizon trade-off analysis. Read-only consultant. |
| `debugger` | sonnet | Root-cause analysis, regression isolation, build error diagnosis |
| `executor` | sonnet | Code implementation, refactoring, feature work. Task tool blocked — works alone. |
| `verifier` | sonnet | Completion evidence, claim validation, test adequacy confirmation |
| `tracer` | sonnet | Evidence-driven causal tracing with competing-hypothesis analysis |

### Review Lane

| Agent | Default model | Role |
|---|---|---|
| `security-reviewer` | sonnet | Vulnerabilities, trust boundaries, authentication/authorisation issues |
| `code-reviewer` | opus | Comprehensive review: logic defects, maintainability, anti-patterns, API contracts, backward compatibility |

### Domain Specialists Lane

| Agent | Default model | Role |
|---|---|---|
| `test-engineer` | sonnet | Test strategy, coverage, flaky-test hardening, TDD workflow |
| `designer` | sonnet | UI/UX architecture, interaction design, component implementation. Never uses generic fonts or clichéd patterns. |
| `writer` | haiku | Documentation, migration notes, user guidance |
| `qa-tester` | sonnet | Interactive CLI/service runtime validation via tmux |
| `scientist` | sonnet | Data analysis, statistical research, hypothesis testing |
| `git-master` | sonnet | Commit strategy, history hygiene, rebase operations |
| `document-specialist` | sonnet | External documentation, API/SDK reference lookup; prefers Context Hub / official docs |
| `code-simplifier` | opus | Code clarity improvement, simplification, maintainability enhancement |

### Coordination Lane

| Agent | Default model | Role |
|---|---|---|
| `critic` | opus | Gap analysis of plans and designs; a plan passes only when the critic can find no remaining gaps |

### Tiered Variants (Delegation-Enforcer Model Routing)

Beyond the 19 base agents, the tiered-agents-v2 design (`docs/TIERED_AGENTS_V2.md`) defines low / medium / high variants for key families. These allow the orchestrator to cheaply route simple tasks to haiku while escalating complex ones to opus automatically.

| Family | Low (haiku) | Base (sonnet) | High (opus) |
|---|---|---|---|
| architect | `architect-low` | `architect` (medium) | `architect` (model=opus) |
| executor | `executor-low` | `executor` | `executor-high` |
| designer | `designer-low` | `designer` | `designer-high` |
| document-specialist | `document-specialist-low` | `document-specialist` | — |
| explore | `explore` (default) | `explore` (model=sonnet) | `explore-high` (model=opus) |

Each tier has explicit complexity boundaries and escalation signals. When an agent detects its task exceeds its tier, it outputs `ESCALATION RECOMMENDED: [reason] → Use oh-my-claudecode:[higher-tier]`, which the orchestrator can act on.

See `docs/TIERED_AGENTS_V2.md` for the full template-based inheritance specification and cost impact analysis (approximately 47% weighted cost reduction compared to routing everything through sonnet).

---

## 7. Commands and CLI

The `omc` binary is defined in `package.json` as pointing to `bridge/cli.cjs` (compiled output of `src/cli/index.ts`). It also registers `oh-my-claudecode` and `omc-cli` as aliases.

The CLI is built with Commander.js and exposes the following top-level subcommands. All subcommands accept `--help` for detailed usage.

### Core subcommands

| Command | One-line description |
|---|---|
| `omc` (bare) | Default action: launch Claude Code with tmux shell integration; passes all args to `launchCommand` |
| `omc launch [args...]` | Explicit launch with flags: `--madmax` / `--yolo` for permissions bypass, `--notify false` to suppress notifications |
| `omc interop` | Open a split-pane tmux session with Claude Code (OMC) on one side and Codex (OMX) on the other |
| `omc ask <provider> <question>` | Route a prompt to `claude`, `codex`, or `gemini` and write an ask artifact; output persisted for CCG/pipeline consumption |
| `omc setup` | Sync all OMC components (hooks, agents, skills); equivalent to running the in-session omc-setup skill from the CLI |
| `omc install [--force]` | Install agents and commands to `~/.claude/`; called automatically by npm postinstall |
| `omc postinstall` | Silent postinstall hook called by npm; does not fail npm install on error |
| `omc info` | Show system information: available agents, enabled features, MCP servers, magic keywords |
| `omc config` | Show current configuration; `--validate` checks for missing env vars, `--paths` shows file locations |
| `omc config-stop-callback <type>` | Configure stop hook callbacks for file / telegram / discord / slack; supports `--profile <name>` for named notification profiles |
| `omc config-notify-profile [name]` | List, show, or delete named notification profiles; `--list`, `--show`, `--delete` |
| `omc version` | Show version, install method, commit hash, and last update check |
| `omc update [--check\|--force]` | Check for and install updates; `--standalone` forces npm path in plugin context; `--clean` purges old cache |
| `omc update-reconcile` | Internal: reconcile runtime state after update; called by `omc update`; `--skip-grace-period` bypasses 24h purge delay |
| `omc test-prompt <prompt>` | Debug prompt enhancement: shows detected magic keywords and the enhanced prompt |
| `omc hud [--watch]` | Run the HUD statusline renderer; `--watch` loops for use in a tmux pane; `--interval <ms>` sets poll rate |
| `omc mission-board [--json]` | Render the opt-in mission board snapshot for the current workspace |
| `omc doctor conflicts [--json]` | Check for plugin coexistence issues and configuration conflicts |

### Team subcommands

The `omc team` command passes all arguments directly to the team command handler (`src/cli/commands/team.ts`). It supports:

| Command | Purpose |
|---|---|
| `omc team [N:agent-type] "<task>"` | Launch N coordinated workers on a task |
| `omc team status <team-name>` | Show team/worker status |
| `omc team shutdown <team-name> [--force]` | Shut down a running team |
| `omc team api <operation> --input '<json>' [--json]` | Low-level team API access (list-tasks, claim-task, complete-task, etc.) |

### Wait subcommands

The `omc wait` command provides rate-limit management and auto-resume.

| Command | Purpose |
|---|---|
| `omc wait` | Show rate-limit status and suggest next action |
| `omc wait --start` | Start the auto-resume daemon (shorthand) |
| `omc wait --stop` | Stop the daemon (shorthand) |
| `omc wait status [--json]` | Detailed rate-limit and daemon status |
| `omc wait daemon start\|stop [-f] [-i <s>]` | Start or stop the background daemon; `-f` foreground, `-i` poll interval |
| `omc wait detect [--json] [-l <lines>]` | Scan tmux sessions for blocked Claude Code sessions |

### Teleport subcommands

The `omc teleport` command provides quick git worktree management.

| Command | Purpose |
|---|---|
| `omc teleport '<ref>'` | Create a git worktree for an issue/PR number or feature branch name |
| `omc teleport list [--json]` | List existing worktrees under `~/Workspace/omc-worktrees/` |
| `omc teleport remove <path> [--force]` | Remove a worktree |

Note: shell-quote the `#` character in issue/PR refs: `omc teleport '#42'`.

### Session subcommands

| Command | Purpose |
|---|---|
| `omc session search <query>` | Full-text search of prior local session transcripts and OMC artifacts; `--since 7d`, `--project all`, `--json`, `--context <chars>` |

### Other notable subcommands

| Command | Purpose |
|---|---|
| `omc ralphthon [args...]` | Autonomous hackathon lifecycle: interview → execute → harden → done |
| `omc autoresearch [args...]` | Thin-supervisor autoresearch with keep / discard / reset parity |

### The `src/commands/index.ts` module

This is the SDK-facing command expansion utility (not the CLI). It provides `expandCommand(name, args)` and `expandCommandPrompt(name, args)` for programmatic use of OMC skills from the Claude Agent SDK, without going through the CLI. Commands are read from `~/.claude/commands/*.md` and expanded by substituting `$ARGUMENTS`.

---

## 8. Hooks and Event Taxonomy

Hooks are the event-driven backbone of OMC. They run as Node.js scripts (`scripts/*.mjs`) invoked by Claude Code's native hook system on eleven lifecycle events. OMC registers hooks in `hooks/hooks.json`.

### Hook events and registered scripts

| Event | OMC scripts registered | Purpose |
|---|---|---|
| `UserPromptSubmit` | `keyword-detector.mjs`, `skill-injector.mjs` | Detect magic keywords in user input; inject skill behaviour |
| `SessionStart` | `session-start.mjs`, `project-memory-session.mjs`, `setup-init.mjs` (matcher: init), `setup-maintenance.mjs` (matcher: maintenance) | Load project memory; inject session context; run first-time setup on init sessions |
| `PreToolUse` | `pre-tool-enforcer.mjs` | Enforce delegation model constraints; inject default model via delegation-enforcer |
| `PermissionRequest` | `permission-handler.mjs` (matcher: Bash) | Handle permission requests for Bash commands |
| `PostToolUse` | `post-tool-verifier.mjs`, `project-memory-posttool.mjs` | Validate tool output; extract and persist project knowledge |
| `PostToolUseFailure` | error recovery script | Error recovery handling |
| `SubagentStart` | subagent-tracker script | Track currently running agents |
| `SubagentStop` | subagent-tracker script | Validate agent output on stop |
| `PreCompact` | pre-compact script | Save notepad and project memory before context compaction |
| `Stop` | stop script | Enforce persistent mode (ralph/ultrawork) — prevents Claude stopping if boulder is active; optional code-simplifier run |
| `SessionEnd` | session-end script | Write session summary JSON; trigger notification callbacks |

Each hook entry in `hooks.json` specifies a `matcher` pattern (`*` matches all input, named strings match specific session types) and a `timeout` in seconds.

### system-reminder injection patterns

Hooks communicate back to the orchestrator by writing to stdout, which Claude Code wraps in `<system-reminder>` tags and appends to the model's context. Key patterns:

| Pattern | Meaning |
|---|---|
| `hook success: Success` | Hook ran normally; proceed as planned |
| `hook additional context: ...` | Informational context; take note |
| `[MAGIC KEYWORD: ralph]` | Keyword detected; execute indicated skill immediately |
| `The boulder never stops` | A persistent mode (ralph or ultrawork) is active; do not stop |

### Persistence mechanisms

Two XML-style tags are available for agents and skills to request durable memory storage:

| Tag | Retention | Mechanism |
|---|---|---|
| `<remember>content</remember>` | 7 days | Written to notepad; re-injected on next session start |
| `<remember priority>content</remember>` | Permanent | Written to notepad with high-priority flag; never pruned automatically |

These tags are processed by the post-tool and stop hooks, which extract the content and call `notepad_write_priority` or `notepad_write_working` as appropriate.

### Kill switches

| Variable | Effect |
|---|---|
| `DISABLE_OMC=1` | Disable all OMC hooks globally |
| `OMC_SKIP_HOOKS=hook1,hook2` | Skip specific named hooks; comma-separated list |

---

## 9. MCP Servers and Integrations

OMC exposes its state management, team API, and code intelligence tools as MCP (Model Context Protocol) servers. These are registered in `~/.claude/settings.json` by the `omc-setup` skill and are available to any Claude Code session that has OMC configured.

### MCP server files

| File | What it exposes |
|---|---|
| `bridge/mcp-server.cjs` | Core OMC state tools: `state_read`, `state_write`, `state_clear`, `state_list_active`, `state_get_status`; notepad tools: `notepad_read`, `notepad_write_priority`, `notepad_write_working`, `notepad_write_manual`, `notepad_prune`, `notepad_stats`; project memory tools: `project_memory_read`, `project_memory_write`, `project_memory_add_note`, `project_memory_add_directive`; trace tools: `trace_timeline`, `trace_summary`; LSP tools: `lsp_diagnostics`, `lsp_diagnostics_directory`, `lsp_document_symbols`, `lsp_workspace_symbols`, `lsp_hover`, `lsp_find_references`, `lsp_servers`; AST tools: `ast_grep_search`, `ast_grep_replace` |
| `bridge/team-bridge.cjs` | Team task management API: `TeamCreate`, `TeamDelete`, `SendMessage`, `TaskCreate`, `TaskList`, `TaskGet`, `TaskUpdate` |
| `bridge/team-mcp.cjs` | Legacy team MCP runtime tools (hard-deprecated; return `deprecated_cli_only` error; use `omc team` CLI instead) |

### OpenClaw gateway routing

The OpenClaw bridge (`src/openclaw/`) normalises hook lifecycle events into a stable signal contract for downstream consumers such as Telegram bots, Discord webhooks, and Slack channels. Full specification: `docs/OPENCLAW-ROUTING.md`.

The payload shape adds a `signal` object alongside the raw `event` field:

```json
{
  "event": "post-tool-use",
  "signal": {
    "kind": "test",
    "name": "test-run",
    "phase": "failed",
    "routeKey": "test.failed",
    "priority": "high"
  }
}
```

High-priority route keys that should be wired to notifications:

- `session.started`, `session.finished`, `session.idle`
- `question.requested`
- `test.started`, `test.finished`, `test.failed`
- `pull-request.started`, `pull-request.created`, `pull-request.failed`
- `tool.failed`

Generic `tool.started` / `tool.finished` are available as low-priority fallbacks. Consumers should filter on `signal.priority === "high"` or specific `signal.routeKey` values rather than routing on raw hook names.

Command gateways receive the payload via the template variable `{{payloadJson}}` or the env var `OPENCLAW_PAYLOAD_JSON`, plus convenience env vars `OPENCLAW_SIGNAL_ROUTE_KEY`, `OPENCLAW_SIGNAL_PHASE`, and `OPENCLAW_SIGNAL_KIND`.

### Notification integrations

OMC supports push notifications through the stop-hook callback system. Configure via `omc config-stop-callback` or the `configure-notifications` skill:

| Channel | Configuration |
|---|---|
| **File** | Saves session summary to disk; supports `{session_id}`, `{date}`, `{time}` path templates; output format: `markdown` or `json` |
| **Telegram** | Bot token + chat ID; supports tag lists for `@mention` routing |
| **Discord** | Webhook URL or Bot API (token + channel ID); supports tag lists |
| **Slack** | Incoming webhook URL; supports tag lists |
| **Generic webhook** | POST with JSON body to any URL |

Named notification profiles allow switching between different notification targets at launch time via `OMC_NOTIFY_PROFILE=<name> claude`. Create profiles with `omc config-stop-callback <type> --profile <name> --enable ...`.

The MCP setup skill (`skills/mcp-setup/SKILL.md`) provides an interactive wizard for configuring common MCP servers (filesystem, web search, GitHub, Exa search) using the `claude mcp add` command-line interface.

---

## 10. State and Memory Model

OMC uses the `.omc/` directory (project-scoped) and `~/.omc/` (user-scoped) for persistent state. Understanding the directory layout is essential for debugging mode transitions and recovering from interrupted sessions.

### Directory structure

```
.omc/
├── state/                         Runtime mode state files (JSON)
│   ├── autopilot-state.json       Autopilot progress: phase, iteration, agents spawned
│   ├── ralph-state.json           Ralph loop state: iteration, max, PRD path
│   ├── team/                      Team task state (per team name)
│   └── sessions/                  Per-session isolated state
│       └── {sessionId}/           Session-specific files; concurrent sessions don't conflict
├── notepad.md                     Compaction-resistant memo pad
├── project-memory.json            Cross-session project knowledge store
├── plans/                         Execution plans, PRDs, test specs
│   ├── prd-*.md                   Ralph PRD files
│   └── test-spec-*.md             Ralph test specifications
├── notepads/                      Per-plan wisdom capture
│   └── {plan-name}/
│       ├── learnings.md           Technical discoveries and patterns
│       ├── decisions.md           Architectural choices and rationale
│       ├── issues.md              Known issues and blockers
│       └── problems.md            Technical debt and cautions
├── autopilot/                     Autopilot phase artifacts
│   └── spec.md                    Expanded requirements spec
├── specs/                         Deep-interview and deep-dive output specs
├── research/                      Research results from sciomc / external-context
├── sessions/                      Session-end summaries written by session-end hook
│   └── {sessionId}.json
└── logs/                          Execution logs
```

**Global state:**

```
~/.omc/
└── state/
    └── {name}.json                User preferences and global config

~/.claude/
└── skills/
    └── omc-learned/               User-level learned skills (portable across projects)
```

### What is runtime vs. version-controlled

Files in `.omc/state/` are runtime and should be gitignored. Files in `.omc/plans/` and `.omc/notepads/` capture planning decisions and are typically version-controlled. `project-memory.json` contains cross-session project knowledge and is version-controlled by convention.

### Centralised state (optional)

By default, state is project-local and is lost if the worktree is deleted. To preserve state across worktree deletions, set:

```bash
export OMC_STATE_DIR="$HOME/.claude/omc"
```

State is then stored at `~/.claude/omc/{project-hash}/` where the hash is derived from the Git remote URL, making the same repository share state across different worktrees on the same machine.

### Notepad

The notepad (`notepad.md`) is the primary cross-compaction persistence mechanism. The `PreCompact` hook saves important context here before Claude Code compresses the context window. After compaction, the notepad contents are re-injected into the session context by the `SessionStart` hook.

MCP tools: `notepad_read`, `notepad_write_priority`, `notepad_write_working`, `notepad_write_manual`, `notepad_prune`, `notepad_stats`.

### Project memory

`project-memory.json` is a structured store for project-level knowledge that persists across sessions. It is loaded at `SessionStart`, updated after tool use (via `PostToolUse` hook), and saved before compaction. MCP tools: `project_memory_read`, `project_memory_write`, `project_memory_add_note`, `project_memory_add_directive`.

The `docs/CLAUDE.md` `<worktree_paths>` section and the AGENTS.md `<tools>` section are the authoritative references for which MCP tool names to use in orchestration.

### Skill scoping: project vs. user

| Scope | Path | When to use |
|---|---|---|
| Project-local | `.omc/skills/` | Skills specific to one repository; version-controlled with the project |
| User-global | `~/.claude/skills/omc-learned/` | Learned skills extracted via the `learner` skill; portable across all projects |
| Plugin-bundled | `skills/` in the OMC plugin directory | Bundled skills shipped with OMC; read-only from the user's perspective |

The compatibility layer also reads project-local skills from `.agents/skills/` for legacy installations.

### Notepad wisdom (plan-scoped knowledge capture)

Each execution plan can have its own notepad directory at `.omc/notepads/{plan-name}/` with four markdown files capturing learnings, decisions, issues, and problems. Entries are timestamped automatically. The full API is documented in `docs/FEATURES.md` §Notepad Wisdom System.

---

## 11. Tier and Delegation Model

### Three model tiers

OMC maps agents to three model tiers, selectable by name or by the orchestrator's routing logic:

| Tier | Typical model | Use for |
|---|---|---|
| LOW | haiku | Fast lookups, narrow checks, simple one-file edits |
| MEDIUM | sonnet | Implementation, debugging, code review, testing |
| HIGH | opus | Architecture, deep analysis, consensus review, complex refactoring |

The tier can be overridden per-delegation using the explicit `model=` parameter on the `Task` tool call.

### Delegation-enforcer

The delegation-enforcer (`docs/DELEGATION-ENFORCER.md`, implemented as a `PreToolUse` hook) automatically injects the correct `model` parameter into every `Task` / `Agent` tool call that omits it. This eliminates the need to remember each agent's default tier.

Lookup is O(1) via a direct hash map. Explicit `model=` values are always preserved. When `OMC_DEBUG=true`, the enforcer emits warnings like `[OMC] Auto-injecting model: sonnet for executor`.

### Delegation categories

Beyond the three tiers, the delegation-categories system (`docs/FEATURES.md` §Delegation Categories) provides semantic task classification that also sets temperature and thinking budget:

| Category | Tier | Temperature | Thinking budget | Use for |
|---|---|---|---|---|
| `visual-engineering` | HIGH | 0.7 | high | UI/UX, frontend, design systems |
| `ultrabrain` | HIGH | 0.3 | max | Complex reasoning, architecture, deep debugging |
| `artistry` | MEDIUM | 0.9 | medium | Creative solutions, brainstorming |
| `quick` | LOW | 0.1 | low | Simple lookups, basic operations |
| `writing` | MEDIUM | 0.5 | medium | Documentation, technical writing |
| `unspecified-low` | LOW | 0.1 | low | Default for simple tasks |
| `unspecified-high` | HIGH | 0.5 | high | Default for complex tasks |

Categories are auto-detected from prompt keywords or can be specified explicitly.

### Delegation rules

The orchestrator's `<delegation_rules>` (from `AGENTS.md`) govern when to delegate vs. act directly:

**Delegate when:** multi-file changes, refactors, debugging, reviews, planning, research, verification, or work that benefits from specialist prompts.

**Act directly when:** trivial operations, small clarifications, quick status checks, or single-command sequential operations.

The AGENTS.md also specifies maximum concurrent child agents (6), the child-agent protocol (read the role prompt from `agents/<name>.md` and pass it in the `spawn_agent` message), and model resolution precedence for team workers.

### Team model resolution precedence

For Claude workers in a team run, model selection follows this precedence (highest to lowest):

1. Explicit `--model` in worker launch args
2. `ANTHROPIC_MODEL` / `CLAUDE_MODEL` env vars
3. Provider tier envs (`CLAUDE_CODE_BEDROCK_SONNET_MODEL`, `ANTHROPIC_DEFAULT_SONNET_MODEL`)
4. `OMC_MODEL_MEDIUM` env var
5. Claude Code default model

---

## 12. Execution Modes Deep-Dive

### Ralph

**Philosophy:** Ralph is inspired by the Sisyphean framing embedded in the package name (`oh-my-claude-sisyphus`). The boulder never stops. The mode is built on the premise that "do your best" is insufficient for critical work, and that only verified completion should terminate a loop. Ralph forces the orchestrator to think in terms of product requirements (what must be true when done) rather than in terms of tasks (what must be done).

**Loop structure:**

1. Ralplan gate: if `.omc/plans/prd-*.md` and `.omc/plans/test-spec-*.md` do not exist, stay in planning phase. Use ralplan to generate them.
2. Write mode state: `state_write({mode: "ralph", active: true, iteration: N, max_iterations: M, current_phase: "execution"})`.
3. Launch ultrawork for parallel execution of pending user stories.
4. On each iteration completion, call `verifier` agent to check all stories. Verifier reads the PRD and tests; returns pass/fail per story.
5. If all stories pass, invoke `cancel` to clean up state and exit.
6. If max iterations exceeded without all passing, transition to `failed` state and surface the blocker to the user.

**Cancel mechanism:** The `/oh-my-claudecode:cancel` skill reads the active state file, identifies the mode, and calls `state_clear(mode="ralph")`. The stop hook is the enforcement layer that prevents premature exit — it reads the state file and, if ralph is active, re-injects "The boulder never stops" into the context.

**Typical use case:** A security remediation that must touch every affected file and pass all security tests. A data migration that must achieve 100% row parity. A refactor that must leave all existing tests green.

**Gotchas:**
- The planning gate is real and blocking: do not attempt to skip it by writing stub PRD files.
- Ralph is expensive. Each iteration spawns ultrawork agents, runs verifier, and writes state. For exploratory work or tasks with soft completion criteria, autopilot or ultrawork alone are more appropriate.
- Max iterations defaults to 10 in the autopilot state machine; the ralph skill does not hardcode this and relies on the verifier to gate.

### Ultrawork

**Philosophy:** Ultrawork is the parallelism primitive. Its philosophy is that a task taking N minutes sequentially should take N/M minutes with M agents, where M is bounded by the number of genuinely independent subtasks. It does not attempt to enforce completion or verify outcomes — those are ralph's responsibilities.

**Loop structure:** Ultrawork decomposes the task into independent subtasks (or receives pre-decomposed subtasks from the caller), launches up to 6 concurrent agents, and collects their outputs. There is no retry logic, no state persistence between runs, and no forced continuation.

**Cancel mechanism:** No persistent state is written by ultrawork itself (the state file is written by whichever wrapping mode — ralph or autopilot — is active). Cancelling ultrawork means cancelling the containing mode.

**Typical use case:** Fixing all type errors across a large codebase simultaneously. Implementing multiple independent API endpoints in parallel. Running parallel code reviews across separate modules.

**Gotchas:**
- Ultrawork agents each have their own context window and do not share state with each other or the parent. They must be given complete, self-contained task descriptions.
- The 6-agent concurrency limit is a Claude Code platform constraint, not an OMC configuration.
- Ultrawork is a component, not a mode with its own state files. It does not appear in `omc wait` output.

### Autopilot

**Philosophy:** Autopilot is the highest-level abstraction: give it a two-to-three line idea and receive working, verified, multi-perspective validated code. It is designed for users who want to describe what they want and return later to a finished result.

**Loop structure (5 phases):**

1. **Expansion** — Analyst and architect sub-agents expand the raw idea into a structured requirements spec saved to `.omc/autopilot/spec.md`. Up to 2 expansion iterations are attempted.
2. **Planning** — Architect creates a detailed execution plan (`.omc/plans/autopilot-impl.md`), validated by critic. Up to 5 architect iterations.
3. **Execution** — Ralph + ultrawork implement the plan. Up to 5 parallel executors.
4. **QA** — UltraQA cycles: qa-tester runs, architect verifies, executor fixes. Up to 5 QA cycles.
5. **Validation** — Three independent validators (functional, security, quality) each return `APPROVED` / `REJECTED` / `NEEDS_FIX`. If any rejects, autopilot loops back to execution with the issues list. Up to 3 validation rounds.

State is persisted to `.omc/state/autopilot-state.json` throughout. Phase transitions are atomic state writes. The session can be resumed after interruption via `canResumeAutopilot()` / `resumeAutopilot()`.

**Cancel mechanism:** `/cancel` invokes `cancelAutopilot()`, which sets `active: false` and preserves the current phase for resume. `clearAutopilot()` removes all state.

**Typical use case:** Greenfield feature development ("build me a REST API with authentication and rate limiting"). New microservice scaffolding. Anything where the user can specify the outcome but wants the system to figure out the how.

**Gotchas:**
- Autopilot's expansion phase may surface assumptions or ambiguities. If `pauseAfterExpansion: true` is set, autopilot will pause for user review before proceeding.
- The validation phase with three independent validator agents can be slow. Set `skipValidation: true` (in config) to omit it for prototype work.
- Autopilot writes many state files. After a successful completion, run `/cancel` to clean them up; otherwise they will affect future `state_list_active` queries.

---

## 13. Performance and Observability

The legacy analytics subsystem (previously `omc-analytics`, `omc cost`, `omc sessions`, `omc export`) was removed in commit `8011af06`. The current monitoring surfaces are:

### Agent Observatory

Real-time visibility into running agents, their tool-call counts, estimated token usage, and cost. Displayed automatically in the HUD when agents are active. Accessible programmatically:

```typescript
import { getAgentObservatory } from 'oh-my-claudecode/hooks/subagent-tracker';
const obs = getAgentObservatory(process.cwd());
// obs.header: "Agent Observatory (3 active, 85% efficiency)"
// obs.lines: per-agent status lines
```

### Session Replay

`.omc/state/agent-replay-*.jsonl` files contain chronological event timelines (per tool call). Used for post-session analysis of agent behaviour without re-running the session.

### Session-end summaries

The `session-end` hook writes `.omc/sessions/{sessionId}.json` after each session completes. This JSON includes a session summary that is also forwarded through configured notification channels (Telegram, Discord, Slack, file, webhook).

### HUD statusline

The HUD (`/oh-my-claudecode:hud setup`) renders a statusline in a dedicated tmux pane. It shows:

```
[OMC] ralph:3/10 | US-002 | ultrawork skill:planner | ctx:67% | agents:2 | todos:2/5
```

Presets: `minimal`, `focused`, `full`. Run `omc hud --watch` from the CLI to start a continuous-polling HUD renderer in a tmux pane.

### Trace MCP tools

`trace_timeline` and `trace_summary` are MCP tools (from `mcp-server.cjs`) that provide chronological agent-turn timelines and aggregate statistics (turn counts, timing, token usage) for the current session.

The canonical guide is `docs/PERFORMANCE-MONITORING.md`. The analytics subsystem entry-point doc is `docs/ANALYTICS-SYSTEM.md`, which confirms the legacy stack is removed and lists the currently supported surfaces.

---

## 14. AI Egress Proxy

The AI egress proxy is a first-class feature, not a bolt-on. It solves a concrete problem: when Claude Code sends prompts to `api.anthropic.com`, those prompts may contain personally identifiable information (names, identification numbers, contact details) or proprietary source code (internal package names, database schema identifiers, codenames, internal API endpoints). Organisations with data-handling obligations cannot allow this data to reach third-party cloud AI infrastructure without mitigation.

The proxy intercepts all outbound Anthropic API traffic, scans and tokenises sensitive content before forwarding, and reverses the tokenisation in the inbound response stream — ensuring that the model sees opaque tokens, not real values, while the developer's tool continues to receive the original values in tool outputs and completions.

Implementation lives in `src/proxy/`. The handover document `docs/proxy/TODO.md` is the authoritative guide to what has been implemented, what is pending, and how to resume.

### The problem

Without the proxy, a developer who asks Claude Code to "refactor this payment service" may inadvertently send:
- Customer email addresses and phone numbers from test fixtures or logs.
- Vietnamese national ID numbers (CCCD), tax codes (MST), or social insurance codes (BHXH) from sample data.
- Internal package import paths that reveal proprietary architecture.
- Database schema identifiers (table names, column names) that constitute trade secrets.
- Codenames for unreleased products or internal systems.

The proxy prevents this egress without requiring the developer to manually scrub their prompts.

### The pipeline

```
Claude Code → omc-proxy (HTTP) → DLP pipeline → api.anthropic.com
                                       │
              ┌───────────────────────┐│┌──────────────────────────┐
              │  1. Allowlist check   ││  (outbound)               │
              │  2. Regex lane        ││                            │
              │  3. Aho-Corasick dict ││  Sensitive values replaced │
              │  4. SQL lane*         ││  with tokens: EMAIL_01,   │
              │  5. AST lane**        ││  PKG_03, SCHEMA_USERS      │
              │  6. Tokenise → vault  ││                            │
              │  7. Audit log (fsync) ││                            │
              │  8. HITL bypass***    ││                            │
              └───────────────────────┘│└──────────────────────────┘
                                       │
              api.anthropic.com responds with tokens
                                       │
              ┌───────────────────────┐│┌──────────────────────────┐
              │  SSE detokeniser      ││  (inbound)                │
              │  Token → original     ││                            │
              │  value from vault     ││  Developer sees real       │
              │  Streamed to Claude   ││  values in output          │
              └───────────────────────┘│└──────────────────────────┘
```

`*` Enabled by `OMC_PROXY_SQL_DLP=1`
`**` Enabled by `OMC_PROXY_AST_DLP=1`
`***` HITL (Human-in-the-Loop) bypass: **planned (P3)**, not yet implemented

### Detection lanes

The proxy runs multiple detection strategies in sequence:

**Regex lane** (`src/proxy/dlp.ts` — `compilePatterns`, `applyPolicy`): Pattern-based detection compiled at startup with `safe-regex` validation to prevent ReDoS. Classifiers shipped:

| Classifier | What it detects |
|---|---|
| `EMAIL` | Email addresses |
| `PHONE` | Phone numbers |
| `CCCD` | Vietnamese national ID (Căn cước công dân) — 12-digit structural heuristic |
| `MST` | Vietnamese tax codes (Mã số thuế) |
| `BHXH` | Vietnamese social insurance codes (Bảo hiểm xã hội) |
| `BANK_ACCOUNT` | Bank account numbers |

**Aho-Corasick dictionary lane** (`src/proxy/dictionary.ts`): Two automata (case-sensitive and case-insensitive) built from a configurable dictionary file (`src/proxy/sample-dictionary.json`). Suitable for codenames, internal project names, partner names. Supports hot-reload via file watcher (planned: Redis pub-sub for distributed reload).

**SQL lane** (`src/proxy/sql-lane.ts`) — behind `OMC_PROXY_SQL_DLP=1`: Parses SQL text using `node-sql-parser`, walks the AST, and tokenises table names, column names, and schema identifiers. Re-serialises to valid SQL with tokens substituted. Preserves SQL parseability.

**AST lane** (`src/proxy/ast-lane.ts`) — behind `OMC_PROXY_AST_DLP=1`: Uses tree-sitter to parse TypeScript, JavaScript, Python, and Java source code; identifies internal import paths and class path references for tokenisation.

### Token vault and round-trip

The vault (`src/proxy/vault.ts`) maps opaque tokens to original values. Tokens follow the pattern `{CLASSIFIER}_{NN}` (e.g., `EMAIL_01`, `PKG_03`). The `InProcessTokenVault` is a conversation-scoped in-memory map with a 24-hour TTL default. Each conversation (derived from the request session ID and body hash) has an isolated namespace.

**Outbound:** `redactAnthropicRequest()` walks the entire JSON request body, replaces each detected value with its vault token, and optionally injects a system prompt instruction telling the model not to reproduce tokens verbatim.

**Inbound SSE:** The `SseDetokenizer` class buffers incoming SSE chunks, parses `data:` lines, and replaces vault tokens with their original values before emitting to the client. A 512-byte rolling hold-back buffer (`HOLD_BACK = 512`, defined at `src/proxy/dlp.ts:488`) prevents split-token edge cases: the buffer grows across chunks within a content block, and on `content_block_stop` the full buffer is rescanned before final flush.

**Non-streaming path:** `detokenizeValue()` walks the parsed response JSON and replaces tokens. Note: the non-streaming path does not apply a DLP scan to the upstream response content (only to the request); this is a known gap documented in the security audit (observation 1076).

### Allowlist

The allowlist (`src/proxy/allowlist.ts`) controls which tools and upstream URLs the proxy will forward. Tool scanning (`scanRequestForBannedTools`, line 323 of `server.ts`) runs before DLP. URL validation (`validateUpstreamUrl`, line 449) runs before forwarding. The proxy refuses to forward to non-allowlisted upstream endpoints.

### Audit log

`src/proxy/audit.ts` writes fsync'd audit log entries for each request/response cycle. The log format includes a counter and timestamp. Full tamper-evidence via HMAC chain is listed as P2 in the migration plan (currently the fsync provides durability but not tamper-evidence).

### Authentication

The proxy enforces bearer-token authentication on all non-`/health` routes using `constantTimeTokenMatch` (`crypto.timingSafeEqual`). The token is set via `OMC_PROXY_CLIENT_TOKEN`. Binding to public interfaces (`0.0.0.0` or `::`) is blocked unless `OMC_PROXY_ALLOW_PUBLIC=1` is explicitly set.

### Starting the proxy

```bash
export ANTHROPIC_API_KEY=sk-ant-...
export OMC_PROXY_CLIENT_TOKEN=$(openssl rand -hex 32)
npx tsx src/proxy/cli.ts start --port 11434
```

### Known gaps and planned work

The following items are explicitly pending as of the HEAD commit (`f4861613`):

| Item | Status |
|---|---|
| Redis-backed `TokenVault` (replace in-process vault for production) | Planned (P2) |
| Vietnamese NER via Presidio + underthesea sidecar | Planned (P2) |
| Dictionary hot-reload via Redis pub-sub | Planned (P2) |
| `purgeExpired()` scheduled timer (method exists, not wired to `setInterval`) | Open TODO |
| HMAC audit chain for NĐ 13/2023 Điều 27 tamper-evidence | Planned (P2, moved from P3) |
| Bypass JWT workflow (15-min, maxUses=1, never for `SECRET.*`) | Planned (P3) |
| KMS envelope encryption for vault DEK/KEK | Planned (P3) |
| Multi-tenant vault isolation | Planned (P3) — partial schema (`tenantId` field) already in `config.ts` |
| Upstream-response DLP scan on direct proxy path | Open gap — currently only the agent-loop path applies Zod validation |
| Vietnamese NER precision/recall gating (≥0.85 / ≥0.70 on dev-context dataset) | Required before enabling underthesea in production |

The `docs/proxy/TODO.md` file is the canonical handover document. The security design document (`docs/proxy/security-design.md`) was planned but had not been committed as of `f4861613`; per the TODO, its content should be generated from the TODO outline.

---

## 15. Agent Team Pipeline

The team pipeline is the canonical multi-agent coordination model in OMC. It applies whenever the `team` skill or `omc team` CLI command is used. The pipeline has five stages with defined transition conditions and a bounded fix loop.

```
team-plan ──► team-prd ──► team-exec ──► team-verify ──► complete
                                              │
                                              ▼ (issues found)
                                          team-fix ──► team-exec (loop)
                                              │
                                              ▼ (max attempts exceeded)
                                            failed
```

**team-plan:** Workers decompose the task into sub-tasks and build a shared task list. Transition when planning and decomposition are complete.

**team-prd:** Acceptance criteria and scope are made explicit. Each task gets clear pass/fail criteria. Transition when all tasks have acceptance criteria.

**team-exec:** Workers claim and execute tasks from the shared list. Atomic task claiming prevents duplicate work. Transition when all tasks reach terminal states (done or failed).

**team-verify:** A dedicated verifier (or set of verifiers) checks all completed work against acceptance criteria. Transition outcomes:
- All pass → `complete`
- Issues found → `team-fix`
- Critical failure → `failed`

**team-fix:** Executor agents fix the flagged issues. Transition outcomes:
- Fixed → back to `team-exec` or `team-verify`
- All issues resolved → `complete`
- Max attempts exceeded → `failed`

**Max attempts:** The fix loop is bounded by a configurable max-attempts count. Exceeding the bound transitions to `failed` with a summary of unresolved issues.

**Terminal states:** `complete`, `failed`, `cancelled`.

**Resume:** If a session is interrupted mid-pipeline, the team skill detects existing team state on reinvocation and resumes from the last incomplete stage.

### Team vs. Swarm

The current `team` mode uses Claude Code's native team infrastructure (built-in `TeamCreate`, `TeamDelete`, `SendMessage`, `TaskCreate`, `TaskList`, `TaskGet`, `TaskUpdate` tools). The legacy `swarm` mode used SQLite-based coordination and is fully removed as of v3.5.3 (PR #1131). All `swarm` references should be replaced with `team`.

### Team ralph linking

`/oh-my-claudecode:team ralph "task"` links team coordination with ralph persistence: the team pipeline runs with ralph's "boulder never stops" guarantee, meaning the team will not report completion until the verifier confirms all acceptance criteria are met.

---

## 16. Compatibility and Migration

### Compatibility layer (`docs/COMPATIBILITY.md`)

The compatibility layer enables OMC to discover, register, and use external plugins, MCP servers, and tools through a four-component system:

- **Discovery system**: Scans `~/.claude/plugins/`, `~/.claude/installed-plugins/`, `~/.claude/settings.json`, and plugin `plugin.json` manifests for plugins, skills, agents, and MCP server configurations.
- **Tool registry**: Central hub with namespace-prefixed tool names (`plugin:tool-name`), priority-based conflict resolution, and short-name lookup.
- **Permission adapter**: Integrates external tools with OMC's permission system; auto-approves known-safe patterns (Context7, filesystem read, Exa search); prompts for dangerous operations; caches decisions.
- **MCP bridge**: JSON-RPC 2.0 over process stdio; spawns server processes, discovers tools and resources, routes invocations.

Plugin manifests (`plugin.json`) declare skills, agents, MCP servers, permissions, and tool definitions. Skills are discovered from `SKILL.md` files; the canonical project-local write target is `.omc/skills/`, with `.agents/skills/` also read for legacy compatibility.

Remote MCP endpoints are supported in the narrow form of `"url": "https://..."` entries in `mcpServers` config. This is not a general multi-host OMC cluster — it is a single remote MCP endpoint supported by the existing MCP bridge.

### Migration guide (`docs/MIGRATION.md`)

The migration guide covers four major migration paths:

**Unreleased: Team MCP runtime deprecation**
The `omc_run_team_start/status/wait/cleanup` MCP tools now return `deprecated_cli_only` errors. Replace with `omc team` CLI commands. The `OMX_ASK_ADVISOR_SCRIPT` / `OMX_ASK_ORIGINAL_TASK` env aliases have a Phase-1 compatibility period with planned hard sunset 2026-06-30; the canonical names are `OMC_ASK_*`.

**v3.5.2 → v3.5.3: Skill consolidation**
Eight deprecated skills were removed: `cancel-autopilot`, `cancel-ralph`, `cancel-ultrawork`, `cancel-ultraqa` (replaced by unified `/cancel`), `omc-default`, `omc-default-global` (replaced by `/omc-setup --local` / `--global`), and `planner` (replaced by `/plan`). The unified `/cancel` command auto-detects the active mode.

**v2.x → v3.0: Package rename and auto-activation**
The major version transition moved from explicit command invocation to keyword-based auto-activation. All 2.x commands continue to work in 3.x. The npm package name `oh-my-claude-sisyphus` was kept unchanged; the project brand moved to `oh-my-claudecode`. Directory paths (`.omc/`, `~/.omc/`) and environment variable names (`OMC_*`) are unchanged.

**v3.x → v4.0 (planned)**
v4.0 is listed as planned with a modular architecture, enhanced agent lifecycle management, unified config schema, and migration tooling. No timeline has been committed in the current codebase.

### CJK IME known issues (`docs/CJK-IME-KNOWN-ISSUES.md`)

Claude Code CLI uses React Ink for terminal UI. React Ink's `TextInput` processes individual keystrokes without IME composition state, meaning CJK users (Korean, Japanese, Chinese, Vietnamese) experience invisible characters during composition, mispositioned composition text, and performance issues.

The root cause is Node.js raw mode (`process.stdin.setRawMode(true)`) which provides only byte-level stdin access with no composition event callbacks.

**Current status (as of August 2025):** Cursor positioning is partially fixed; character visibility is not fixed; a fundamental fix requires patching React Ink or adopting an alternative input method.

**Recommended workaround:** Compose CJK text in an external editor (VS Code, Notes) and paste into Claude Code. The paste path bypasses the raw mode limitation. Alternatively, use Claude Code through IDE integrations that may handle IME differently.

---

## 17. Testing, Build, and Release Pipeline

### Test suite

Tests use [vitest](https://vitest.dev/) and are co-located with source under `src/**/__tests__/`. Run with:

```bash
npm run test:run       # run all tests once
npm test               # vitest watch mode
npm run test:coverage  # with coverage report
npm run test:ui        # vitest UI
```

The proxy test suite was at 94 tests as of commit `8f04b25a` (token vault + dictionary lane). The delegation-enforcer tests are marked as skipped pending implementation completion (`docs/MIGRATION.md` v3.5.5 notes).

### Build system

The build pipeline compiles TypeScript and bundles several bridge artifacts:

```bash
npm run build
```

This runs in sequence:
1. `tsc` — TypeScript compilation to `dist/`
2. `build-skill-bridge.mjs` — Builds `bridge/` skill bridge entry point
3. `build-mcp-server.mjs` — Builds `bridge/mcp-server.cjs`
4. `build-bridge-entry.mjs` — Builds the main bridge entry
5. `compose-docs.mjs` — Assembles composite documentation files
6. `build:runtime-cli` — Builds `bridge/runtime-cli.cjs`
7. `build:team-server` — Builds `bridge/team-bridge.cjs` and `bridge/team-mcp.cjs`
8. `build:cli` — Builds `bridge/cli.cjs` (the `omc` binary)

The `prepublishOnly` script runs `build` and `compose-docs` before every npm publish.

### Benchmarks

Prompt quality benchmarks live in `benchmarks/`:

```bash
npm run bench:prompts            # run all prompt benchmarks
npm run bench:prompts:save       # save as baseline
npm run bench:prompts:compare    # compare against baseline
```

### Sync-metadata system (`docs/SYNC-SYSTEM.md`)

`package.json` is the single source of truth for version, repository URL, and package name. The `sync-metadata` script propagates these values to `README.md`, `docs/REFERENCE.md`, `.github/CLAUDE.md`, `docs/ARCHITECTURE.md`, and `CHANGELOG.md`:

```bash
npm run sync-metadata             # apply updates
npm run sync-metadata:verify      # CI check — fails if any file is out of sync
npm run sync-metadata:dry-run     # preview changes without writing
```

The `version` lifecycle script in `package.json` runs `scripts/sync-version.sh` automatically on `npm version` bumps.

### Release workflow

```bash
npm run release                  # interactive release script
# or via the skill:
/oh-my-claudecode:release <version|patch|minor>
```

The `release.ts` script handles version bumping, changelog updates, and tagging. CHANGELOG conventions follow Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:`, etc.).

The `sync-featured-contributors` script generates a featured contributors section from GitHub contribution data:

```bash
npm run sync-featured-contributors
npm run sync-featured-contributors:verify
npm run sync-featured-contributors:dry-run
```

---

## 18. Not in This Repo

To avoid confusion for new engineers, the following are explicitly outside the scope of this repository:

- **A replacement for Claude Code**: OMC is a plugin that extends Claude Code. It requires Claude Code to be installed and running. It does not replace the Claude Code CLI, the Anthropic API, or any model.
- **A new language model**: OMC is orchestration software. It uses Claude models (haiku, sonnet, opus) through the standard Anthropic API. It does not train, fine-tune, or serve any model.
- **A self-hosted server**: OMC is not a server you deploy and run continuously. The AI egress proxy (`src/proxy/`) is an optional local HTTP proxy started on demand; it is not a production SaaS or a container you push to Kubernetes.
- **A fork with changes to Claude's behaviour**: OMC does not patch Claude Code, modify model weights, or intercept model inference. It only operates at the hook and prompt level.
- **Cross-platform support for Windows native terminal**: The CLI's tmux-dependent features (team workers, omc interop, omc wait detect) require tmux, which is not available on native Windows. A Win32 warning is displayed at startup. WSL is the recommended path for Windows users.
- **A standalone MCP server**: OMC exposes MCP tools, but only for consumption by Claude Code agents running under the OMC plugin. It is not a standalone MCP server for arbitrary MCP clients.
- **Persistent cloud infrastructure**: All OMC state is local (`.omc/` directory or `$OMC_STATE_DIR`). There is no OMC cloud sync, no OMC account, and no shared state between developers.

---

## 19. Where to Go Next

| Document | Contents | When to read it |
|---|---|---|
| `docs/ARCHITECTURE.md` | Four-system diagram (hooks, skills, agents, state); agent selection guide; skill layer composition; hook registration; state directory structure | First stop after this overview — canonical system design |
| `docs/REFERENCE.md` | Developer API reference: notepad wisdom API, delegation categories API, directory diagnostics API, dynamic prompt generation, session resume, autopilot state machine API | When building integrations or extending OMC programmatically |
| `docs/FEATURES.md` | Internal API documentation with TypeScript types and usage examples for all major features | Deep dive on autopilot, notepad, delegation categories |
| `docs/TIERED_AGENTS_V2.md` | Tiered-agent architecture design: template-based inheritance, capability boundaries, escalation signals, cost analysis | When adding new agents or tuning the routing model |
| `docs/DELEGATION-ENFORCER.md` | Delegation-enforcer middleware: API, agent model mapping, debug mode, hook integration | When debugging wrong-model invocations |
| `docs/OPENCLAW-ROUTING.md` | Signal contract for Telegram/Discord/Slack routing; payload shape; route key taxonomy; noise reduction | When setting up notification integrations |
| `docs/PERFORMANCE-MONITORING.md` | Agent Observatory, Session Replay, HUD integration, debugging techniques | When diagnosing slow or inefficient multi-agent runs |
| `docs/ANALYTICS-SYSTEM.md` | Confirms legacy analytics stack is removed; lists currently supported monitoring surfaces | When looking for `omc cost` or `omc sessions` (both removed) |
| `docs/SYNC-SYSTEM.md` | Metadata sync system: how version/count metadata propagates from `package.json` to docs | When bumping version or updating contributor counts |
| `docs/COMPATIBILITY.md` | Plugin discovery, tool registry, permission adapter, MCP bridge | When integrating external plugins or MCP servers |
| `docs/MIGRATION.md` | Migration paths: team MCP deprecation, v3.5.3 skill removals, v2.x → v3.0, v3.x → v4.0 | When upgrading from an older OMC version |
| `docs/CJK-IME-KNOWN-ISSUES.md` | Root cause analysis and workarounds for Korean/Japanese/Chinese/Vietnamese input issues | When supporting CJK-language users |
| `docs/LOCAL_PLUGIN_INSTALL.md` | Local development checkout install flow; worktree-aware plugin registration | When developing OMC itself from a local checkout |
| `docs/proxy/TODO.md` | Proxy feature handover: what is implemented, what is pending, how to resume | When working on the AI egress proxy |
| `CHANGELOG.md` | Version history with conventional commit entries | When reviewing what changed between versions |
| `AGENTS.md` (root) | Condensed agent catalogue + tools + team pipeline + commit protocol used at runtime | The file Claude reads during sessions; keep in sync with `docs/ARCHITECTURE.md` |

---

## 20. Document Provenance

**Commit hash at time of writing:** `f4861613` (feat(proxy): add AST detection lane behind OMC_PROXY_AST_DLP)

**Files read to produce this document:**

- `README.md` (primary user-facing readme — note: file contains only line 1 in the working tree; full content obtained from the AGENTS.md sister file)
- `AGENTS.md` (root) — full read
- `CLAUDE.md` (root) — full read
- `package.json` — full read
- `docs/ARCHITECTURE.md` — full read
- `docs/FEATURES.md` — full read (Developer API Reference)
- `docs/TIERED_AGENTS_V2.md` — full read
- `docs/DELEGATION-ENFORCER.md` — full read
- `docs/OPENCLAW-ROUTING.md` — full read
- `docs/COMPATIBILITY.md` — full read
- `docs/MIGRATION.md` — full read
- `docs/CJK-IME-KNOWN-ISSUES.md` — full read
- `docs/ANALYTICS-SYSTEM.md` — top section (39 lines)
- `docs/PERFORMANCE-MONITORING.md` — top section (60 lines)
- `docs/SYNC-SYSTEM.md` — top section (60 lines)
- `docs/LOCAL_PLUGIN_INSTALL.md` — top section (80 lines)
- `docs/proxy/TODO.md` — full read
- `src/cli/index.ts` — full read (CLI subcommand definitions)
- `src/commands/index.ts` — full read (SDK command expansion)
- `src/proxy/server.ts` — smart outline + observations 1075, 1076
- `src/proxy/dlp.ts` — smart outline + observations 1075, 1076
- `src/proxy/vault.ts` — smart outline + observations 1075, 1076
- `src/proxy/config.ts` — smart outline + observations 1075
- `src/proxy/audit.ts` — observation 1074 (security audit findings)
- `src/proxy/allowlist.ts` — observation 1074
- `hooks/hooks.json` — full read (parsed for hook event inventory)
- `skills/*/SKILL.md` — frontmatter + first paragraph for all 32 skill directories
- Prior session memory observations 1074, 1075, 1076 (proxy security audit, code cross-check) via `mcp__plugin_claude-mem_mcp-search__get_observations`

**Files skipped and why:**

- `dist/` — compiled output; no feature information beyond what the source provides
- `node_modules/` — third-party dependencies; not product features
- `tests/fixtures/` — test data; no feature information
- `benchmarks/` body — benchmark scripts; covered by summary in §17
- `benchmark/` body — same
- `docs/proxy/security-design.md` — file does not exist at HEAD; the TODO.md handover document was read instead
- `docs/REFERENCE.md` — skimmed via docs/FEATURES.md (which is the same document content); the canonical section titles and API shapes are captured in §10 and §11
- `bridge/cli.cjs` — compiled/bundled CommonJS output; source is `src/cli/index.ts` which was read instead
- `src/proxy/agent-loop.ts`, `src/proxy/ast-lane.ts`, `src/proxy/sql-lane.ts`, `src/proxy/dictionary.ts` — covered by smart outlines and memory observations; line-level code not needed for feature catalogue
- `CHANGELOG.md` body — release history; not required for feature catalogue; referenced in §17
- `assets/`, `missions/`, `research/`, `seminar/`, `shellmark/`, `examples/` — project-specific artefacts, not product feature definitions
- `README.de.md`, `README.es.md`, `README.fr.md`, `README.it.md`, `README.ja.md`, `README.ko.md`, `README.pt.md`, `README.ru.md`, `README.tr.md`, `README.vi.md`, `README.zh.md` — translations of README.md; no additional feature information

**Accuracy notes for follow-up:**

- `docs/proxy/security-design.md` does not exist at HEAD. The TODO.md indicates it should be written from the outline in that file. Section §14 is based on the TODO outline, source code outlines, and the security audit observations (1074, 1075, 1076).
- The security audit (observation 1074) identified 8 blocking issues in the design doc including one factual error: the CCCD "Luhn-like checksum" claim is incorrect (no such algorithm exists in Thông tư 59/2021/TT-BCA). Section §14 avoids repeating this claim.
- Observation 1075 found that `server.ts` returns HTTP 500 (not 503) for missing upstream API key. This is a discrepancy between the planned design (NFR-8) and the implementation.
- Observation 1076 found that Zod upstream response validation is only applied on the agent-loop path, not on the direct proxy path. The non-streaming proxy path applies `detokenizeValue` but no DLP scan on the upstream response.
- The `vault.ts` `purgeExpired()` method exists but is not wired to a `setInterval` in `server.ts`. This is an open TODO.
- `config.ts` already has an optional `tenantId` field in `DictionaryEntrySchema`, providing partial multi-tenant schema support despite the migration plan listing it as P3.
- The `docs/ANALYTICS-SYSTEM.md` file explicitly states the legacy analytics stack (`omc-analytics`, `omc cost`, `omc sessions`) was removed in commit `8011af06`. Any reference to these commands in older docs or scripts should be treated as removed.
