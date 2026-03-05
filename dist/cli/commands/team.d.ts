/**
 * omc team CLI subcommand
 *
 * Full team lifecycle for `omc team`:
 *   omc team [N:agent-type] "task"          Start team (spawns tmux worker panes)
 *   omc team status <team-name>             Monitor team status
 *   omc team shutdown <team-name> [--force] Shutdown team
 *   omc team api <operation> --input '...'  Worker CLI API
 */
/**
 * Main team subcommand handler.
 * Routes:
 *   omc team [N:agent-type] "task"          -> Start team
 *   omc team status <team-name>             -> Monitor
 *   omc team shutdown <team-name> [--force] -> Shutdown
 *   omc team api <operation> [--input] ...  -> Worker CLI API
 */
export declare function teamCommand(args: string[]): Promise<void>;
//# sourceMappingURL=team.d.ts.map