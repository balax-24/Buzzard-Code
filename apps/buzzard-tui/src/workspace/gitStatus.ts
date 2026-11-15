import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

export interface GitChange {
  path: string;
  status: 'modified' | 'added' | 'deleted' | 'untracked';
  insertions?: number;
  deletions?: number;
}

export interface GitSummary {
  isRepo: boolean;
  branch: string;
  changes: GitChange[];
  totalInsertions: number;
  totalDeletions: number;
}

export async function getGitSummary(workspace: string): Promise<GitSummary> {
  try {
    // 1. Get current branch
    const { stdout: branchOut } = await execFileAsync('git', ['rev-parse', '--abbrev-ref', 'HEAD'], {
      cwd: workspace,
      timeout: 3000,
    });
    const branch = branchOut.trim() || 'detached';

    // 2. Get status porcelain
    const { stdout: statusOut } = await execFileAsync('git', ['status', '--porcelain'], {
      cwd: workspace,
      timeout: 3000,
    });

    const changes: GitChange[] = [];
    const lines = statusOut.split('\n');
    for (const line of lines) {
      if (!line || line.length < 3) continue;
      const xy = line.slice(0, 2);
      const filePath = line.slice(3).trim();

      let status: GitChange['status'] = 'modified';
      if (xy.includes('?')) status = 'untracked';
      else if (xy.includes('A')) status = 'added';
      else if (xy.includes('D')) status = 'deleted';

      changes.push({ path: filePath, status });
    }

    // 3. Get diff stat
    let totalInsertions = 0;
    let totalDeletions = 0;
    try {
      const { stdout: diffStat } = await execFileAsync('git', ['diff', '--numstat'], {
        cwd: workspace,
        timeout: 3000,
      });
      const numLines = diffStat.split('\n');
      for (const nl of numLines) {
        const parts = nl.trim().split(/\s+/);
        if (parts.length >= 3) {
          const ins = parseInt(parts[0] || '0', 10) || 0;
          const del = parseInt(parts[1] || '0', 10) || 0;
          const p = parts[2] || '';
          totalInsertions += ins;
          totalDeletions += del;

          const changeItem = changes.find((c) => c.path === p);
          if (changeItem) {
            changeItem.insertions = ins;
            changeItem.deletions = del;
          }
        }
      }
    } catch {
      // Diff stat optional
    }

    return {
      isRepo: true,
      branch,
      changes,
      totalInsertions,
      totalDeletions,
    };
  } catch {
    return {
      isRepo: false,
      branch: 'none',
      changes: [],
      totalInsertions: 0,
      totalDeletions: 0,
    };
  }
}

export async function getFullGitDiff(workspace: string): Promise<string> {
  try {
    const { stdout } = await execFileAsync('git', ['diff'], {
      cwd: workspace,
      timeout: 5000,
      maxBuffer: 1024 * 1024 * 5, // 5MB max
    });
    return stdout;
  } catch (err: any) {
    return `Error retrieving git diff: ${err.message}`;
  }
}
