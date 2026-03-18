import { describe, it, expect, afterEach } from 'vitest';
import { spawnSync } from 'node:child_process';
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const REPO_ROOT = join(__dirname, '..', '..');
const SETUP_SCRIPT = join(REPO_ROOT, 'scripts', 'setup-claude-md.sh');

const tempRoots: string[] = [];

function createPluginFixture(claudeMdContent: string) {
  const root = mkdtempSync(join(tmpdir(), 'omc-setup-claude-md-'));
  tempRoots.push(root);

  const pluginRoot = join(root, 'plugin');
  const projectRoot = join(root, 'project');
  const homeRoot = join(root, 'home');

  mkdirSync(join(pluginRoot, 'scripts'), { recursive: true });
  mkdirSync(join(pluginRoot, 'docs'), { recursive: true });
  mkdirSync(projectRoot, { recursive: true });
  mkdirSync(homeRoot, { recursive: true });

  copyFileSync(SETUP_SCRIPT, join(pluginRoot, 'scripts', 'setup-claude-md.sh'));
  writeFileSync(join(pluginRoot, 'docs', 'CLAUDE.md'), claudeMdContent);

  return {
    pluginRoot,
    projectRoot,
    homeRoot,
    scriptPath: join(pluginRoot, 'scripts', 'setup-claude-md.sh'),
  };
}

afterEach(() => {
  while (tempRoots.length > 0) {
    const root = tempRoots.pop();
    if (root) {
      rmSync(root, { recursive: true, force: true });
    }
  }
});

describe('setup-claude-md.sh (issue #1572)', () => {
  it('installs the canonical docs/CLAUDE.md content with OMC markers', () => {
    const fixture = createPluginFixture(`<!-- OMC:START -->
<!-- OMC:VERSION:9.9.9 -->

# Canonical CLAUDE
Use the real docs file.
<!-- OMC:END -->
`);

    const result = spawnSync('bash', [fixture.scriptPath, 'local'], {
      cwd: fixture.projectRoot,
      env: {
        ...process.env,
        HOME: fixture.homeRoot,
      },
      encoding: 'utf-8',
    });

    expect(result.status).toBe(0);

    const installedPath = join(fixture.projectRoot, '.claude', 'CLAUDE.md');
    expect(existsSync(installedPath)).toBe(true);

    const installed = readFileSync(installedPath, 'utf-8');
    expect(installed).toContain('<!-- OMC:START -->');
    expect(installed).toContain('<!-- OMC:END -->');
    expect(installed).toContain('<!-- OMC:VERSION:9.9.9 -->');
    expect(installed).toContain('# Canonical CLAUDE');
  });

  it('refuses to install a canonical source that lacks OMC markers', () => {
    const fixture = createPluginFixture(`# oh-my-claudecode (OMC) v9.9.9 Summary

This is a summarized CLAUDE.md without markers.
`);

    const result = spawnSync('bash', [fixture.scriptPath, 'local'], {
      cwd: fixture.projectRoot,
      env: {
        ...process.env,
        HOME: fixture.homeRoot,
      },
      encoding: 'utf-8',
    });

    expect(result.status).not.toBe(0);
    expect(`${result.stdout}\n${result.stderr}`).toContain('missing required OMC markers');
    expect(existsSync(join(fixture.projectRoot, '.claude', 'CLAUDE.md'))).toBe(false);
  });

  it('adds a local git exclude block for .omc artifacts while preserving .omc/skills', () => {
    const fixture = createPluginFixture(`<!-- OMC:START -->
<!-- OMC:VERSION:9.9.9 -->

# Canonical CLAUDE
Use the real docs file.
<!-- OMC:END -->
`);

    const gitInit = spawnSync('git', ['init'], {
      cwd: fixture.projectRoot,
      env: {
        ...process.env,
        HOME: fixture.homeRoot,
      },
      encoding: 'utf-8',
    });
    expect(gitInit.status).toBe(0);

    const result = spawnSync('bash', [fixture.scriptPath, 'local'], {
      cwd: fixture.projectRoot,
      env: {
        ...process.env,
        HOME: fixture.homeRoot,
      },
      encoding: 'utf-8',
    });

    expect(result.status).toBe(0);

    const excludePath = join(fixture.projectRoot, '.git', 'info', 'exclude');
    expect(existsSync(excludePath)).toBe(true);

    const excludeContents = readFileSync(excludePath, 'utf-8');
    expect(excludeContents).toContain('# BEGIN OMC local artifacts');
    expect(excludeContents).toContain('.omc/*');
    expect(excludeContents).toContain('!.omc/skills/');
    expect(excludeContents).toContain('!.omc/skills/**');
    expect(excludeContents).toContain('# END OMC local artifacts');
  });

  it('does not duplicate the local git exclude block on repeated local setup runs', () => {
    const fixture = createPluginFixture(`<!-- OMC:START -->
<!-- OMC:VERSION:9.9.9 -->

# Canonical CLAUDE
Use the real docs file.
<!-- OMC:END -->
`);

    const gitInit = spawnSync('git', ['init'], {
      cwd: fixture.projectRoot,
      env: {
        ...process.env,
        HOME: fixture.homeRoot,
      },
      encoding: 'utf-8',
    });
    expect(gitInit.status).toBe(0);

    const firstRun = spawnSync('bash', [fixture.scriptPath, 'local'], {
      cwd: fixture.projectRoot,
      env: {
        ...process.env,
        HOME: fixture.homeRoot,
      },
      encoding: 'utf-8',
    });
    expect(firstRun.status).toBe(0);

    const secondRun = spawnSync('bash', [fixture.scriptPath, 'local'], {
      cwd: fixture.projectRoot,
      env: {
        ...process.env,
        HOME: fixture.homeRoot,
      },
      encoding: 'utf-8',
    });
    expect(secondRun.status).toBe(0);

    const excludeContents = readFileSync(join(fixture.projectRoot, '.git', 'info', 'exclude'), 'utf-8');
    expect(excludeContents.match(/# BEGIN OMC local artifacts/g)).toHaveLength(1);
  });
});
