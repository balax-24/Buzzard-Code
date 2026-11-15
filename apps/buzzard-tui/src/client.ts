import { spawn, ChildProcess } from 'node:child_process';
import * as path from 'node:path';
import * as fs from 'node:fs';
import * as readline from 'node:readline';
import {
  InitializeResult,
  ApprovalRequest,
  ToolEvent,
  RunFinished,
  TaskItem,
} from './types.js';

export interface RuntimeClientEvents {
  onDelta?: (text: string) => void;
  onToolStart?: (event: ToolEvent) => void;
  onToolEnd?: (event: ToolEvent) => void;
  onApprovalRequest?: (request: ApprovalRequest) => void;
  onEvidenceReport?: (report: string) => void;
  onRunFinished?: (result: RunFinished) => void;
  onError?: (err: Error) => void;
  onExit?: (code: number | null) => void;
}

export class RuntimeClient {
  private proc: ChildProcess | null = null;
  private nextId = 1;
  private pendingRequests = new Map<number, { resolve: (val: any) => void; reject: (err: any) => void }>();
  private events: RuntimeClientEvents = {};
  private workspace: string;
  private rl: readline.Interface | null = null;

  constructor(workspace: string, events: RuntimeClientEvents = {}) {
    this.workspace = path.resolve(workspace);
    this.events = events;
  }

  public setEvents(events: RuntimeClientEvents) {
    this.events = { ...this.events, ...events };
  }

  private resolvePythonPath(): { python: string; cwd: string } {
    let current = this.workspace;
    for (let i = 0; i < 5; i++) {
      const winVenv = path.join(current, '.venv', 'Scripts', 'python.exe');
      const nixVenv = path.join(current, '.venv', 'bin', 'python');
      if (fs.existsSync(winVenv)) return { python: winVenv, cwd: current };
      if (fs.existsSync(nixVenv)) return { python: nixVenv, cwd: current };
      const parent = path.dirname(current);
      if (parent === current) break;
      current = parent;
    }
    return { python: process.platform === 'win32' ? 'python' : 'python3', cwd: this.workspace };
  }

  public start(): Promise<InitializeResult> {
    return new Promise((resolve, reject) => {
      const { python, cwd } = this.resolvePythonPath();
      const args = ['-m', 'security_agent.cli.main', 'serve', '--stdio'];

      try {
        this.proc = spawn(python, args, {
          cwd,
          stdio: ['pipe', 'pipe', 'pipe'],
          env: {
            ...process.env,
            PYTHONUNBUFFERED: '1',
            PYTHONIOENCODING: 'utf-8',
            PYTHONPATH: cwd + (process.env.PYTHONPATH ? path.delimiter + process.env.PYTHONPATH : ''),
          },
        });
      } catch (err) {
        return reject(err);
      }

      this.proc.on('error', (err) => {
        this.events.onError?.(err);
        reject(err);
      });

      this.proc.on('exit', (code) => {
        this.events.onExit?.(code);
      });

      this.proc.stderr?.on('data', () => {
        // Discard or debug stderr so pipe never blocks
      });

      if (!this.proc.stdout) {
        return reject(new Error('Process stdout unavailable'));
      }

      this.rl = readline.createInterface({
        input: this.proc.stdout,
        crlfDelay: Infinity,
      });

      this.rl.on('line', (line: string) => {
        const trimmed = line.trim();
        if (!trimmed) return;
        try {
          const msg = JSON.parse(trimmed);
          this.handleMessage(msg);
        } catch {
          // Ignore unparseable non-JSON lines
        }
      });

      // Send initialize RPC
      this.sendRequest<InitializeResult>('initialize', {
        protocolVersion: '1.0',
        workspace: this.workspace,
      })
        .then(resolve)
        .catch(reject);
    });
  }

  private handleMessage(msg: any) {
    if (msg.id !== undefined && (msg.result !== undefined || msg.error !== undefined)) {
      const pending = this.pendingRequests.get(msg.id);
      if (pending) {
        this.pendingRequests.delete(msg.id);
        if (msg.error) {
          pending.reject(new Error(msg.error.message || JSON.stringify(msg.error)));
        } else {
          pending.resolve(msg.result);
        }
      }
      return;
    }

    if (msg.method) {
      this.handleNotification(msg.method, msg.params || {});
    }
  }

  private handleNotification(method: string, params: any) {
    switch (method) {
      case 'run/delta':
        this.events.onDelta?.(params.text || '');
        break;
      case 'tool/started':
        this.events.onToolStart?.({
          runId: params.runId,
          tool: params.tool,
          arguments: params.arguments,
          status: 'running',
        });
        break;
      case 'tool/completed':
        this.events.onToolEnd?.({
          runId: params.runId,
          tool: params.tool,
          durationMs: params.durationMs,
          exitCode: params.exitCode,
          preview: params.preview,
          status: 'completed',
        });
        break;
      case 'tool/failed':
        this.events.onToolEnd?.({
          runId: params.runId,
          tool: params.tool,
          durationMs: params.durationMs,
          exitCode: params.exitCode,
          preview: params.preview,
          status: 'failed',
        });
        break;
      case 'approval/requested':
        this.events.onApprovalRequest?.({
          requestId: params.requestId,
          tool: params.tool,
          arguments: params.arguments,
          riskClass: params.riskClass || 'medium',
          canAllowForSession: !!params.canAllowForSession,
        });
        break;
      case 'run/evidence':
        this.events.onEvidenceReport?.(params.report || '');
        break;
      case 'run/finished':
        this.events.onRunFinished?.({
          runId: params.runId,
          status: params.status,
          finalAnswer: params.finalAnswer,
          error: params.error,
          metrics: params.metrics,
        });
        break;
    }
  }

  public sendRequest<T = any>(method: string, params: any = {}): Promise<T> {
    return new Promise((resolve, reject) => {
      if (!this.proc || !this.proc.stdin || this.proc.killed) {
        return reject(new Error('Runtime process is not running'));
      }
      const id = this.nextId++;
      this.pendingRequests.set(id, { resolve, reject });
      const payload = JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n';
      this.proc.stdin.write(payload, 'utf-8');
    });
  }

  public async startRun(goal: string, planMode?: boolean, attempts?: number): Promise<{ runId: string }> {
    return this.sendRequest('run/start', { goal, planMode, attempts });
  }

  public async cancelRun(): Promise<{ cancelled: boolean }> {
    return this.sendRequest('run/cancel', {});
  }

  public async respondApproval(requestId: string, decision: 'allow' | 'allow_session' | 'deny'): Promise<{ accepted: boolean }> {
    return this.sendRequest('approval/respond', { requestId, decision });
  }

  public async setPlanMode(enabled: boolean): Promise<{ planMode: boolean }> {
    return this.sendRequest('session/setPlanMode', { enabled });
  }

  public async listTasks(): Promise<{ tasks: TaskItem[] }> {
    return this.sendRequest('task/list', {});
  }

  public async resumeTask(taskId: string): Promise<{ runId: string }> {
    return this.sendRequest('run/resume', { taskId });
  }

  public async undoEdit(): Promise<{ message: string }> {
    return this.sendRequest('edit/undo', {});
  }

  public async stop(): Promise<void> {
    try {
      if (this.proc && !this.proc.killed) {
        await this.sendRequest('shutdown', {}).catch(() => {});
        this.proc.kill('SIGTERM');
      }
    } catch {
      // Ignore cleanup error
    } finally {
      this.proc = null;
      if (this.rl) {
        this.rl.close();
        this.rl = null;
      }
    }
  }
}
